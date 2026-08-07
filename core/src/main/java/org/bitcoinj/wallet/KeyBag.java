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

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.ECKey;

import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptError;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptPattern;
import org.jspecify.annotations.Nullable;

import java.util.Objects;

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
     *            only look for given usage (currently {@link ScriptType#P2PKH} or
     *            {@link ScriptType#P2WPKH}) or {@code null} if we don't care
     * @return found key or null if no such key was found.
     */
    @Nullable
    ECKey findKeyFromPubKeyHash(byte[] pubKeyHash, @Nullable ScriptType scriptType);

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

    /**
     * Alias for getOutpoint().getConnectedRedeemData(keyBag)
     *
     * @param transactionInput
     * @see KeyBag#getConnectedRedeemData(TransactionOutPoint)
     */
    @Nullable
    default RedeemData getConnectedRedeemData(TransactionInput transactionInput) throws ScriptException {
        return getConnectedRedeemData(transactionInput.getOutpoint());
    }

    /**
     * Returns the RedeemData identified in the connected output, for either P2PKH, P2WPKH, P2PK
     * or P2SH scripts.
     * If the script forms cannot be understood, throws ScriptException.
     *
     * @param transactionOutPoint
     * @return a RedeemData or null if the connected data cannot be found in the wallet.
     */
    @Nullable
    default RedeemData getConnectedRedeemData(TransactionOutPoint transactionOutPoint) throws ScriptException {
        TransactionOutput connectedOutput = transactionOutPoint.getConnectedOutput();
        Objects.requireNonNull(connectedOutput, "Input is not connected so cannot retrieve key");
        Script connectedScript = connectedOutput.getScriptPubKey();
        if (ScriptPattern.isP2PKH(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromP2PKH(connectedScript);
            return RedeemData.of(findKeyFromPubKeyHash(addressBytes, ScriptType.P2PKH), connectedScript);
        } else if (ScriptPattern.isP2WPKH(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromP2WH(connectedScript);
            return RedeemData.of(findKeyFromPubKeyHash(addressBytes, ScriptType.P2WPKH), connectedScript);
        } else if (ScriptPattern.isP2PK(connectedScript)) {
            byte[] pubkeyBytes = ScriptPattern.extractKeyFromP2PK(connectedScript);
            return RedeemData.of(findKeyFromPubKey(pubkeyBytes), connectedScript);
        } else if (ScriptPattern.isP2SH(connectedScript)) {
            byte[] scriptHash = ScriptPattern.extractHashFromP2SH(connectedScript);
            return findRedeemDataFromScriptHash(scriptHash);
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Could not understand form of connected output script: " + connectedScript);
        }
    }

    /**
     * Returns the ECKey identified in the connected output, for either P2PKH, P2WPKH or P2PK scripts.
     * For P2SH scripts you can use {@link KeyBag#getConnectedRedeemData(TransactionOutPoint)} and then get the
     * key from RedeemData.
     * If the script form cannot be understood, throws ScriptException.
     *
     * @param transactionOutPoint
     * @return an ECKey or null if the connected key cannot be found in the wallet.
     */
    @Nullable
    default ECKey getConnectedKey(TransactionOutPoint transactionOutPoint) throws ScriptException {
        TransactionOutput connectedOutput = transactionOutPoint.getConnectedOutput();
        Objects.requireNonNull(connectedOutput, "Input is not connected so cannot retrieve key");
        Script connectedScript = connectedOutput.getScriptPubKey();
        if (ScriptPattern.isP2PKH(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromP2PKH(connectedScript);
            return findKeyFromPubKeyHash(addressBytes, ScriptType.P2PKH);
        } else if (ScriptPattern.isP2WPKH(connectedScript)) {
            byte[] addressBytes = ScriptPattern.extractHashFromP2WH(connectedScript);
            return findKeyFromPubKeyHash(addressBytes, ScriptType.P2WPKH);
        } else if (ScriptPattern.isP2PK(connectedScript)) {
            byte[] pubkeyBytes = ScriptPattern.extractKeyFromP2PK(connectedScript);
            return findKeyFromPubKey(pubkeyBytes);
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Could not understand form of connected output script: " + connectedScript);
        }
    }
}
