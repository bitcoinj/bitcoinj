/*
 * Copyright 2014 The bitcoinj authors.
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

import org.bitcoinj.core.ECKey;
import org.bitcoinj.script.Script;

import javax.annotation.Nullable;

/**
 * A KeyBag is simply an object that can map public keys, their 160-bit hashes and script hashes to ECKey
 * and {@link RedeemData} objects.
 */
public interface KeyBag {
    /**
     * Locates a keypair from the keychain given the hash of the public key, and (optionally) by usage for a specific
     * script type. This is needed when finding out which key we need to use to redeem a transaction output.
     *
     * @param pubKeyHash
     *            hash of the keypair to look for
     * @param scriptType
     *            only look for given usage (currently {@link Script.ScriptType#P2PKH} or
     *            {@link Script.ScriptType#P2WPKH}) or {@code null} if we don't care
     * @return found key or null if no such key was found.
     */
    @Nullable
    ECKey findKeyFromPubKeyHash(byte[] pubKeyHash, @Nullable Script.ScriptType scriptType);

    /**
     * Locates a keypair from the keychain given the raw public key bytes.
     *
     * @return ECKey or null if no such key was found.
     */
    @Nullable
    ECKey findKeyFromPubKey(byte[] pubKey);

    /**
     * Locates a redeem data (redeem script and keys) from the keychain given the hash of the script.
     * This is needed when finding out which key and script we need to use to locally sign a P2SH transaction input.
     * It is assumed that wallet should not have more than one private key for a single P2SH tx for security reasons.
     *
     * Returns RedeemData object or null if no such data was found.
     */
    @Nullable
    RedeemData findRedeemDataFromScriptHash(byte[] scriptHash);

}
