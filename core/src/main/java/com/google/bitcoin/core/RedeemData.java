/**
 * Copyright 2014 Kosta Korenkov
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
package com.google.bitcoin.core;

import com.google.bitcoin.script.Script;

import javax.annotation.Nullable;
import java.util.List;

/**
 * This class aggregates portion of data required to spend transaction output.
 *
 * For pay-to-address and pay-to-pubkey transactions it will has only single key and no redeem script.
 * For multisignature transactions there will be multiple keys one of which will be a full key and the rest are watch only.
 * In theory, it's possible for one party to possess several private keys for the same transaction, but this will eliminate
 * multisig's main benefit of enhanced security, so it's not expected.
 * For P2SH transactions there also will be a redeem script.
 */
public class RedeemData {
    @Nullable private Script redeemScript;
    private List<ECKey> keys;

    private RedeemData(List<ECKey> keys, @Nullable Script redeemScript) {
        this.redeemScript = redeemScript;
        this.keys = keys;
    }

    public static RedeemData of(List<ECKey> keys, @Nullable Script redeemScript) {
        return new RedeemData(keys, redeemScript);
    }

    @Nullable
    public Script getRedeemScript() {
        return redeemScript;
    }

    public List<ECKey> getKeys() {
        return keys;
    }

    /**
     * Returns the first key that has private bytes
     */
    public ECKey getFullKey() {
        for (ECKey key : keys) {
            try {
                if (key.getPrivKey() != null)
                    return key;
            } catch (IllegalStateException e) {
                // no private bytes. Proceed to the next key
            }
        }
        return null;
    }
}
