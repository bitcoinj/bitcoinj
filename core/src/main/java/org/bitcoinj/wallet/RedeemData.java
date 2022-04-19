/*
 * Copyright 2014 Kosta Korenkov
 * Copyright 2019 Andreas Schildbach
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

package org.bitcoinj.wallet;

import com.google.common.base.MoreObjects;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptPattern;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * This class aggregates data required to spend transaction output.
 *
 * For P2PKH and P2PK transactions it will have only a single key and CHECKSIG program as redeemScript.
 * For multisignature transactions there will be multiple keys one of which will be a full key and the rest are watch only,
 * redeem script will be a CHECKMULTISIG program. Keys will be sorted in the same order they appear in
 * a program (lexicographical order).
 */
public class RedeemData {
    public final Script redeemScript;
    public final List<ECKey> keys;

    private RedeemData(List<ECKey> keys, Script redeemScript) {
        this.redeemScript = redeemScript;
        List<ECKey> sortedKeys = new ArrayList<>(keys);
        Collections.sort(sortedKeys, ECKey.PUBKEY_COMPARATOR);
        this.keys = sortedKeys;
    }

    public static RedeemData of(List<ECKey> keys, Script redeemScript) {
        return new RedeemData(keys, redeemScript);
    }

    /**
     * Creates RedeemData for P2PKH, P2WPKH or P2PK input. Provided key is a single private key needed
     * to spend such inputs.
     */
    public static RedeemData of(ECKey key, Script redeemScript) {
        checkArgument(ScriptPattern.isP2PKH(redeemScript)
                || ScriptPattern.isP2WPKH(redeemScript) || ScriptPattern.isP2PK(redeemScript));
        return key != null ? new RedeemData(Collections.singletonList(key), redeemScript) : null;
    }

    /**
     * Returns the first key that has private bytes
     */
    public ECKey getFullKey() {
        for (ECKey key : keys)
            if (key.hasPrivKey())
                return key;
        return null;
    }

    @Override
    public String toString() {
        final MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this).omitNullValues();
        helper.add("redeemScript", redeemScript);
        helper.add("keys", keys);
        return helper.toString();
    }
}
