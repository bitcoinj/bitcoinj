/*
 * Copyright 2019 John L. Jegutanis
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

/*
 * Ported from the Bitcoin Core project:
 *   Copyright (c) 2009-2019 The Bitcoin Core developers
 *   Distributed under the MIT software license, see the accompanying
 *   file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

package org.bitcoinj.core;

import com.google.common.annotations.Beta;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.bitcoinj.core.PartiallySignedTransaction.*;
import static org.bitcoinj.core.Utils.uint32ToByteStreamLE;

/**
 * A class for PSBTs which contain per input information.
 *
 * Note: this is an experimental "beta" API and could change in future releases
 * */
@Beta
public class PSBTInput extends ChildMessage {
    public @Nullable Transaction nonWitnessUtxo;
    public TransactionOutput witnessUtxo;
    public Script witnessScript;
    public Script finalScriptSig;
    public Script redeemScript;
    public TransactionWitness finalScriptWitness;
    public Map<ECKey, KeyOriginInfo> hdKeyPaths;
    public Map<ECKey, TransactionSignature> partialSigs;
    public Map<RawBytes, RawBytes> unknown;
    public long sighashType;

    public PSBTInput(NetworkParameters params) {
        super(params);
        witnessUtxo = TransactionOutput.createNull(params);
        witnessScript = Script.EMPTY;
        finalScriptSig = Script.EMPTY;
        redeemScript = Script.EMPTY;
        finalScriptWitness = TransactionWitness.EMPTY;
        hdKeyPaths = new LinkedHashMap<>();
        partialSigs = new LinkedHashMap<>();
        unknown = new LinkedHashMap<>();
    }

    public PSBTInput(NetworkParameters params, PartiallySignedTransaction psbt, byte[] payload, int offset,
                     MessageSerializer serializer) {
        super(params, payload, offset, psbt, serializer, UNKNOWN_LENGTH);
    }

    /**
     * @return true is this PSBT input is sane
     */
    public boolean isSane() {
        // Cannot have both witness and non-witness utxos
        if (!witnessUtxo.isNull() && nonWitnessUtxo != null) return false;

        // If we have a witnessScript or a scriptWitness, we must also have a witness utxo
        if (!witnessScript.isEmpty() && witnessUtxo.isNull()) return false;
        if (!finalScriptWitness.isEmpty() && witnessUtxo.isNull()) return false;

        return true;
    }

    @Override
    protected void parse() throws ProtocolException {
        witnessUtxo = TransactionOutput.createNull(params);
        witnessScript = Script.EMPTY;
        finalScriptSig = Script.EMPTY;
        redeemScript = Script.EMPTY;
        finalScriptWitness = TransactionWitness.EMPTY;
        hdKeyPaths = new LinkedHashMap<>();
        partialSigs = new LinkedHashMap<>();
        unknown = new LinkedHashMap<>();

        // Used for duplicate key detection
        HashSet<RawBytes> keyLookup = new HashSet<>();

        // Read loop
        boolean foundSeparator = false;
        while (hasMoreBytes()) {
            byte[] key = readByteArray();

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.length == 0) {
                foundSeparator = true;
                break;
            }

            // First byte of key is the type
            byte type = key[0];

            // Do stuff based on type
            switch (type) {
                case PSBT_IN_NON_WITNESS_UTXO:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input non-witness utxo already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Non-witness utxo key is more than one byte type");
                    }
                    byte[] nonWitnessUtxoBytes = readByteArray();
                    nonWitnessUtxo = serializer.makeTransaction(nonWitnessUtxoBytes);
                    break;
                case PSBT_IN_WITNESS_UTXO:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input witness utxo already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Witness utxo key is more than one byte type");
                    }
                    witnessUtxo = new TransactionOutput(params, null, readByteArray(), 0, serializer);
                    break;
                case PSBT_IN_PARTIAL_SIG:
                    // Make sure that the key is the size of pubkey + 1
                    if (key.length != ECKey.PUBLIC_KEY_SIZE + 1 && key.length != ECKey.COMPRESSED_PUBLIC_KEY_SIZE + 1) {
                        throw new ProtocolException(
                                "Size of key was not the expected size for the type partial signature pubkey");
                    }
                    // Read in the pubkey from key
                    ECKey ecKey;
                    try {
                        ecKey = ECKey.fromPublicOnly(Arrays.copyOfRange(key, 1, key.length));
                    } catch(IllegalArgumentException e) {
                        throw new ProtocolException("Invalid pubkey", e);
                    }
                    if (partialSigs.containsKey(ecKey)) {
                        throw new ProtocolException(
                                "Duplicate Key, input partial signature for pubkey already provided");
                    }

                    // Read in the signature from value
                    byte[] partialSigBytes = readByteArray();
                    TransactionSignature sig;
                    try {
                        sig = TransactionSignature.decodeFromBitcoin(partialSigBytes, true, true);
                    } catch (SignatureDecodeException e) {
                        throw new ProtocolException(e);
                    }

                    // Add to list
                    partialSigs.put(ecKey, sig);
                    break;
                case PSBT_IN_SIGHASH:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input sighash type already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Sighash type key is more than one byte type");
                    }

                    // The value length must be 4
                    if (readVarInt() != 4) {
                        throw new ProtocolException("Invalid sighash value length");
                    }
                    sighashType = readUint32();
                    break;
                case PSBT_IN_REDEEMSCRIPT:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input redeemScript already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Input redeemScript key is more than one byte type");
                    }
                    redeemScript = new Script(readByteArray());
                    break;
                case PSBT_IN_WITNESSSCRIPT:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input witnessScript already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Input witnessScript key is more than one byte type");
                    }
                    witnessScript = new Script(readByteArray());
                    break;
                case PSBT_IN_BIP32_DERIVATION:
                    // Also does the key length and duplication checks
                    parseHDKeyPaths(this, key, hdKeyPaths);
                    break;
                case PSBT_IN_SCRIPTSIG:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input final scriptSig already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Final scriptSig key is more than one byte type");
                    }
                    finalScriptSig = new Script(readByteArray());
                    break;
                case PSBT_IN_SCRIPTWITNESS:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input final ScriptWitness already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Final ScriptWitness key is more than one byte type");
                    }
                    // Read the stated size of the witness and calculate where the cursor should end up after parsing it
                    long witnessSize = readVarInt();
                    long cursorEnd = witnessSize + cursor;
                    // Parse the witness
                    long pushCount = readVarInt();
                    TransactionWitness witness = new TransactionWitness((int) pushCount);
                    for (int y = 0; y < pushCount; y++) {
                        witness.setPush(y, readByteArray());
                    }
                    // Check that the witness length is correct
                    if (cursorEnd != cursor) {
                        throw new ProtocolException("Size of ScriptWitness did not match the stated size");
                    }
                    finalScriptWitness = witness;
                    break;
                // Unknown stuff
                default:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, key for unknown value already provided");
                    }
                    unknown.put(RawBytes.wrap(key), RawBytes.wrap(readByteArray()));
            }
        }

        if (!foundSeparator) {
            throw new ProtocolException("Separator is missing at the end of an input map");
        }

        // The total length of the input
        length = cursor - offset;
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        // Write the utxo
        // If there is a non-witness utxo, then don't add the witness one.
        if (nonWitnessUtxo != null) {
            serializeToVector(stream, PSBT_IN_NON_WITNESS_UTXO);
            serializeToVector(stream, nonWitnessUtxo.unsafeBitcoinSerialize());
        } else if (!witnessUtxo.isNull()) {
            serializeToVector(stream, PSBT_IN_WITNESS_UTXO);
            serializeToVector(stream, witnessUtxo.unsafeBitcoinSerialize());
        }

        if (finalScriptSig.isEmpty() && finalScriptWitness.isEmpty()) {
            // Write any partial signatures
            for (Map.Entry<ECKey, TransactionSignature> sigPair : partialSigs.entrySet()) {
                byte[] key = sigPair.getKey().getPubKey();

                // Write VarInt for the size of PSBT_IN_PARTIAL_SIG + key
                stream.write(new VarInt(key.length + 1).encode());
                stream.write(PSBT_IN_PARTIAL_SIG);
                stream.write(key);

                // Value
                serializeToVector(stream, sigPair.getValue().encodeToBitcoin());
            }

            // Write the sighash type
            if (sighashType > 0) {
                serializeToVector(stream, PSBT_IN_SIGHASH);
                stream.write(0x04); // VarInt for 4 bytes
                uint32ToByteStreamLE(sighashType, stream);
            }

            // Write redeem script
            if (!redeemScript.isEmpty()) {
                serializeToVector(stream, PSBT_IN_REDEEMSCRIPT);
                serializeToVector(stream, redeemScript.getProgram());
            }

            // Write witness script
            if (!witnessScript.isEmpty()) {
                serializeToVector(stream, PSBT_IN_WITNESSSCRIPT);
                serializeToVector(stream, witnessScript.getProgram());
            }

            //Write any HD keypaths
            serializeHDKeyPaths(stream, hdKeyPaths, PSBT_IN_BIP32_DERIVATION);
        }

        //Write the witness script
        if (!finalScriptSig.isEmpty()) {
            serializeToVector(stream, PSBT_IN_SCRIPTSIG);
            serializeToVector(stream, finalScriptSig.getProgram());
        }

        //Write script witness
        if (!finalScriptWitness.isEmpty()) {
            serializeToVector(stream, PSBT_IN_SCRIPTWITNESS);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            finalScriptWitness.bitcoinSerializeToStream(bos);
            serializeToVector(stream, bos.toByteArray());
        }

        serializeUnknown(stream, unknown);

        stream.write(PSBT_SEPARATOR);
    }

    public void merge(PSBTInput psbtInput) {
        if (nonWitnessUtxo != null && psbtInput.nonWitnessUtxo != null) {
            nonWitnessUtxo = psbtInput.nonWitnessUtxo.copy();
        }
        if (witnessUtxo.isNull() && !psbtInput.witnessUtxo.isNull()) {
            witnessUtxo = psbtInput.witnessUtxo;
            nonWitnessUtxo = null; // Clear out any non-witness utxo when we set a witness one.
        }
        // Use putAll here as the used objects are immutable
        partialSigs.putAll(psbtInput.partialSigs);
        hdKeyPaths.putAll(psbtInput.hdKeyPaths);
        copyUnknown(psbtInput.unknown, unknown);

        if (redeemScript.isEmpty() && !psbtInput.redeemScript.isEmpty()) {
            redeemScript = psbtInput.redeemScript.copy();
        }
        if (witnessScript.isEmpty() && !psbtInput.witnessScript.isEmpty()) {
            witnessScript = psbtInput.witnessScript.copy();
        }
        if (finalScriptSig.isEmpty() && !psbtInput.finalScriptSig.isEmpty()) {
            finalScriptSig = psbtInput.finalScriptSig.copy();
        }
        if (finalScriptWitness.isEmpty() && !psbtInput.finalScriptWitness.isEmpty()) {
            finalScriptWitness = psbtInput.finalScriptWitness.copy();
        }
    }

    public boolean isComplete() {
        return !finalScriptSig.isEmpty() || !finalScriptWitness.isEmpty();
    }
}
