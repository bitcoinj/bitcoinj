/*
 * Copyright 2019 Giannis L. Jegutanis
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
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.SignatureDecodeException;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.jspecify.annotations.Nullable;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.bitcoinj.base.internal.Buffers.readLengthPrefixedBytes;
import static org.bitcoinj.base.internal.Buffers.writeLengthPrefixedBytes;
import static org.bitcoinj.base.internal.ByteUtils.readUint32;
import static org.bitcoinj.core.PartiallySignedTransaction.*;

/**
 * A class for PSBTs which contain per input information.
 * <i>Note: this is an experimental "beta" API and could change in future releases</i>
 * */
@Beta
public class PsbtInput {
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

    public PsbtInput() {
        witnessUtxo = TransactionOutput.createNull();
        witnessScript = Script.EMPTY;
        finalScriptSig = Script.EMPTY;
        redeemScript = Script.EMPTY;
        finalScriptWitness = TransactionWitness.EMPTY;
        hdKeyPaths = new LinkedHashMap<>();
        partialSigs = new LinkedHashMap<>();
        unknown = new LinkedHashMap<>();
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

    /*
     * Deserialize a PSBT Input from a buffer
     *
     * @param payload the buffer
     * @return the PSBT Input
     * @throws ProtocolException for malformed PSBTs
     */
    public static PsbtInput read(ByteBuffer payload) throws ProtocolException {
        PsbtInput input = new PsbtInput();

        // Used for duplicate key detection
        HashSet<RawBytes> keyLookup = new HashSet<>();

        // Read loop
        boolean foundSeparator = false;
        while (payload.hasRemaining()) {
            byte[] key = readLengthPrefixedBytes(payload);

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
                    byte[] nonWitnessUtxoBytes = readLengthPrefixedBytes(payload);
                    input.nonWitnessUtxo = Transaction.read(ByteBuffer.wrap(nonWitnessUtxoBytes));
                    break;
                case PSBT_IN_WITNESS_UTXO:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input witness utxo already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Witness utxo key is more than one byte type");
                    }
                    input.witnessUtxo = TransactionOutput.read(ByteBuffer.wrap(readLengthPrefixedBytes(payload)), null);
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
                    if (input.partialSigs.containsKey(ecKey)) {
                        throw new ProtocolException(
                                "Duplicate Key, input partial signature for pubkey already provided");
                    }

                    // Read in the signature from value
                    byte[] partialSigBytes = readLengthPrefixedBytes(payload);
                    TransactionSignature sig;
                    try {
                        sig = TransactionSignature.decodeFromBitcoin(partialSigBytes, true, true);
                    } catch (SignatureDecodeException e) {
                        throw new ProtocolException(e);
                    }

                    // Add to list
                    input.partialSigs.put(ecKey, sig);
                    break;
                case PSBT_IN_SIGHASH_TYPE:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input sighash type already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Sighash type key is more than one byte type");
                    }

                    // The value length must be 4
                    if (VarInt.read(payload).longValue() != 4) {
                        throw new ProtocolException("Invalid sighash value length");
                    }
                    input.sighashType = readUint32(payload);
                    break;
                case PSBT_IN_REDEEM_SCRIPT:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input redeemScript already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Input redeemScript key is more than one byte type");
                    }
                    input.redeemScript = Script.parse(readLengthPrefixedBytes(payload));
                    break;
                case PSBT_IN_WITNESS_SCRIPT:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input witnessScript already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Input witnessScript key is more than one byte type");
                    }
                    input.witnessScript = Script.parse(readLengthPrefixedBytes(payload));
                    break;
                case PSBT_IN_BIP32_DERIVATION:
                    // Also does the key length and duplication checks
                    parseHDKeyPaths(payload, key, input.hdKeyPaths);
                    break;
                case PSBT_IN_FINAL_SCRIPTSIG:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input final scriptSig already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Final scriptSig key is more than one byte type");
                    }
                    input.finalScriptSig = Script.parse(readLengthPrefixedBytes(payload));
                    break;
                case PSBT_IN_FINAL_SCRIPTWITNESS:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, input final ScriptWitness already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Final ScriptWitness key is more than one byte type");
                    }
                    // Read the stated size of the witness and calculate where the cursor should end up after parsing it
                    long witnessSize = VarInt.read(payload).longValue();
                    long positionEnd = witnessSize + payload.position();
                    // Read the witness
                    TransactionWitness witness = TransactionWitness.read(payload);
                    // Check that the witness length is correct
                    if (positionEnd != payload.position()) {
                        throw new ProtocolException("Size of ScriptWitness did not match the stated size");
                    }
                    input.finalScriptWitness = witness;
                    break;
                // Unknown stuff
                default:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, key for unknown value already provided");
                    }
                    input.unknown.put(RawBytes.wrap(key), RawBytes.wrap(readLengthPrefixedBytes(payload)));
            }
        }

        if (!foundSeparator) {
            throw new ProtocolException("Separator is missing at the end of an input map");
        }

        return input;
    }

    /**
     * @return the size of the serialized message.
     */
    public int messageSize() {
        int size = 0;
        // If there is a non-witness utxo, then don't add the witness one.
        if (nonWitnessUtxo != null) {
            int dataSize = nonWitnessUtxo.messageSize();
            // 2 bytes key + varint + data
            size += 2 + VarInt.sizeOf(dataSize) + dataSize;
        } else if (!witnessUtxo.isNull()) {
            int dataSize = witnessUtxo.messageSize();
            // 2 bytes key + varint + data
            size += 2 + VarInt.sizeOf(dataSize) + dataSize;
        }

        if (finalScriptSig.isEmpty() && finalScriptWitness.isEmpty()) {
            // Size of any partial signatures
            for (Map.Entry<ECKey, TransactionSignature> sigPair : partialSigs.entrySet()) {
                // Key size is PSBT_IN_PARTIAL_SIG + pub key size
                int keyLen = sigPair.getKey().getPubKey().length + 1;
                size += VarInt.sizeOf(keyLen) + keyLen;

                // Value size. Encoding is not very efficient
                int valueLen = sigPair.getValue().encodeToBitcoin().length;
                size += VarInt.sizeOf(valueLen) + valueLen;
            }

            // Size of the sighash type
            if (sighashType > 0) {
                // The size is (varint + PSBT_IN_SIGHASH) + (varint + sighashType)
                size += 1 + 1 + 1 + 4;
            }

            // Size of the redeem script
            if (!redeemScript.isEmpty()) {
                int scriptSize = redeemScript.size();
                // The size is (varint + PSBT_IN_REDEEMSCRIPT) + (varint + redeemScript)
                size += 1 + 1 + VarInt.sizeOf(scriptSize) + scriptSize;
            }

            // Size of witness script
            if (!witnessScript.isEmpty()) {
                int scriptSize = witnessScript.size();
                // The size is (varint + PSBT_IN_WITNESSSCRIPT) + (varint + witnessScript)
                size += 1 + 1 + VarInt.sizeOf(scriptSize) + scriptSize;
            }

            // Size of any HD keypaths
            size += sizeOfHDKeyPaths(hdKeyPaths);
        }

        //Write the witness script
        if (!finalScriptSig.isEmpty()) {
            int sigSize = finalScriptSig.size();
            // The size is (varint + PSBT_IN_SCRIPTSIG) + (varint + finalScriptSig)
            size += 1 + 1 + VarInt.sizeOf(sigSize) + sigSize;
        }

        //Write script witness
        if (!finalScriptWitness.isEmpty()) {
            int witnessSize = finalScriptWitness.messageSize();
            // The size is (varint + PSBT_IN_SCRIPTWITNESS) + (varint + finalScriptSig)
            size += 1 + 1 + VarInt.sizeOf(witnessSize) + witnessSize;
        }

        // Size of unknowns
        size += sizeOfUnknown(unknown);

        // Separator is 1 byte
        size += 1;

        return size;
    }

    /**
     * Write this PSBT input into the given buffer.
     * @param buf the buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the message doesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        // Write the utxo
        // If there is a non-witness utxo, then don't add the witness one.
        if (nonWitnessUtxo != null) {
            writeLengthPrefixedBytes(buf, new byte[]{PSBT_IN_NON_WITNESS_UTXO});
            VarInt.of(nonWitnessUtxo.messageSize()).write(buf);
            nonWitnessUtxo.write(buf);
        } else if (!witnessUtxo.isNull()) {
            writeLengthPrefixedBytes(buf, new byte[]{PSBT_IN_WITNESS_UTXO});
            VarInt.of(witnessUtxo.messageSize()).write(buf);
            witnessUtxo.write(buf);
        }

        if (finalScriptSig.isEmpty() && finalScriptWitness.isEmpty()) {
            // Write any partial signatures
            for (Map.Entry<ECKey, TransactionSignature> sigPair : partialSigs.entrySet()) {
                byte[] key = sigPair.getKey().getPubKey();

                // Write VarInt for the size of PSBT_IN_PARTIAL_SIG + key
                VarInt.of(key.length + 1).write(buf);
                buf.put(PSBT_IN_PARTIAL_SIG);
                buf.put(key);

                // Value
                writeLengthPrefixedBytes(buf, sigPair.getValue().encodeToBitcoin());
            }

            // Write the sighash type
            if (sighashType > 0) {
                writeLengthPrefixedBytes(buf, new byte[]{PSBT_IN_SIGHASH_TYPE});
                buf.put((byte) 0x04); // VarInt for 4 bytes
                ByteUtils.writeInt32LE(sighashType, buf);
            }

            // Write redeem script
            if (!redeemScript.isEmpty()) {
                writeLengthPrefixedBytes(buf, new byte[]{PSBT_IN_REDEEM_SCRIPT});
                writeLengthPrefixedBytes(buf, redeemScript.program());
            }

            // Write witness script
            if (!witnessScript.isEmpty()) {
                writeLengthPrefixedBytes(buf, new byte[]{PSBT_IN_WITNESS_SCRIPT});
                writeLengthPrefixedBytes(buf, witnessScript.program());
            }

            //Write any HD keypaths
            serializeHDKeyPaths(buf, hdKeyPaths, PSBT_IN_BIP32_DERIVATION);
        }

        //Write the witness script
        if (!finalScriptSig.isEmpty()) {
            writeLengthPrefixedBytes(buf, new byte[]{PSBT_IN_FINAL_SCRIPTSIG});
            writeLengthPrefixedBytes(buf, finalScriptSig.program());
        }

        //Write script witness
        if (!finalScriptWitness.isEmpty()) {
            writeLengthPrefixedBytes(buf, new byte[]{PSBT_IN_FINAL_SCRIPTWITNESS});
            // Witness must be prefixed with a varint and written as raw bytes
            VarInt.of(finalScriptWitness.messageSize()).write(buf);
            finalScriptWitness.write(buf);
        }

        writeUnknown(buf, unknown);

        buf.put(PSBT_SEPARATOR);

        return buf;
    }

    /**
     * Merge another psbt input in to this one
     * @param psbtInput the other psbt
     */
    void mergeInto(PsbtInput psbtInput) {
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
