/**
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.wallet;

import com.google.bitcoin.core.*;
import com.google.bitcoin.script.Script;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.LinkedList;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A coin selector that takes all coins assigned to keys created before the given timestamp.
 * Used as part of the implementation of {@link Wallet#setKeyRotationTime(java.util.Date)}.
 */
public class KeyTimeCoinSelector implements CoinSelector {
    private static final Logger log = LoggerFactory.getLogger(KeyTimeCoinSelector.class);

    /** A number of inputs chosen to avoid hitting {@link com.google.bitcoin.core.Transaction.MAX_STANDARD_TX_SIZE} */
    public static final int MAX_SIMULTANEOUS_INPUTS = 600;

    private final long unixTimeSeconds;
    private final Wallet wallet;
    private final boolean ignorePending;

    public KeyTimeCoinSelector(Wallet wallet, long unixTimeSeconds, boolean ignorePending) {
        this.unixTimeSeconds = unixTimeSeconds;
        this.wallet = wallet;
        this.ignorePending = ignorePending;
    }

    @Override
    public CoinSelection select(BigInteger target, LinkedList<TransactionOutput> candidates) {
        try {
            LinkedList<TransactionOutput> gathered = Lists.newLinkedList();
            BigInteger valueGathered = BigInteger.ZERO;
            for (TransactionOutput output : candidates) {
                if (ignorePending && !isConfirmed(output))
                    continue;
                // Find the key that controls output, assuming it's a regular pay-to-pubkey or pay-to-address output.
                // We ignore any other kind of exotic output on the assumption we can't spend it ourselves.
                final Script scriptPubKey = output.getScriptPubKey();
                ECKey controllingKey;
                if (scriptPubKey.isSentToRawPubKey()) {
                    controllingKey = wallet.findKeyFromPubKey(scriptPubKey.getPubKey());
                } else if (scriptPubKey.isSentToAddress()) {
                    controllingKey = wallet.findKeyFromPubHash(scriptPubKey.getPubKeyHash());
                } else {
                    log.info("Skipping tx output {} because it's not of simple form.", output);
                    continue;
                }
                checkNotNull(controllingKey, "Coin selector given output as candidate for which we lack the key");
                if (controllingKey.getCreationTimeSeconds() >= unixTimeSeconds) continue;
                // It's older than the cutoff time so select.
                valueGathered = valueGathered.add(output.getValue());
                gathered.push(output);
                if (gathered.size() >= MAX_SIMULTANEOUS_INPUTS) {
                    log.warn("Reached {} inputs, going further would yield a tx that is too large, stopping here.", gathered.size());
                    break;
                }
            }
            return new CoinSelection(valueGathered, gathered);
        } catch (ScriptException e) {
            throw new RuntimeException(e);  // We should never have problems understanding scripts in our wallet.
        }
    }

    private boolean isConfirmed(TransactionOutput output) {
        return output.getParentTransaction().getConfidence().getConfidenceType().equals(TransactionConfidence.ConfidenceType.BUILDING);
    }
}
