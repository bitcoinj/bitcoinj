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
package com.google.bitcoin.wallet;

import com.google.bitcoin.core.RedeemData;

import javax.annotation.Nullable;

/**
 * A MultisigKeyBag is a KeyBag that can additionally map hashes of redeem scripts to actual Script and keys
 * used to create that script.
 */
public interface MultisigKeyBag extends KeyBag {

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
