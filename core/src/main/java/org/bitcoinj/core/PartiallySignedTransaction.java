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
import com.google.common.collect.ImmutableList;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.ECKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.jspecify.annotations.Nullable;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.*;

import static org.bitcoinj.base.internal.Buffers.*;

/**
 * A class that implements the BIP-174 spec "Partially Signed Bitcoin Transaction Format"
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki">BIP-0174</a>
 * <i>Note: this is an experimental "beta" API and could change in future releases</i>
 */
@Beta
public class PartiallySignedTransaction {
    // PSBT Constants
    // Magic bytes
    final static byte[] PSBT_MAGIC_BYTES = {'p', 's', 'b', 't', (byte) 0xff};
    // Global types
    final static byte PSBT_GLOBAL_UNSIGNED_TX = 0x00;
    // Input types
    final static byte PSBT_IN_NON_WITNESS_UTXO = 0x00;
    final static byte PSBT_IN_WITNESS_UTXO = 0x01;
    final static byte PSBT_IN_PARTIAL_SIG = 0x02;
    final static byte PSBT_IN_SIGHASH_TYPE = 0x03;
    final static byte PSBT_IN_REDEEM_SCRIPT = 0x04;
    final static byte PSBT_IN_WITNESS_SCRIPT = 0x05;
    final static byte PSBT_IN_BIP32_DERIVATION = 0x06;
    final static byte PSBT_IN_FINAL_SCRIPTSIG = 0x07;
    final static byte PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
    // Output types
    final static byte PSBT_OUT_REDEEMSCRIPT = 0x00;
    final static byte PSBT_OUT_WITNESSSCRIPT = 0x01;
    final static byte PSBT_OUT_BIP32_DERIVATION = 0x02;
    // The separator is 0x00. Reading this in means that the unserializer can interpret it
    // as a 0 length key which indicates that this is the separator. The separator has no value.
    final static byte PSBT_SEPARATOR = 0x00;

    public Transaction tx;
    public ArrayList<PsbtInput> inputs;
    public ArrayList<PsbtOutput> outputs;
    public Map<RawBytes, RawBytes> unknown;

    public PartiallySignedTransaction(Transaction unsignedTx) {
        // The PSBT tx must not serialize witnesses, so drop them if needed
        tx = copyAsUnsignedTx(unsignedTx);

        // Init inputs
        int numInputs = tx.getInputs().size();
        inputs = new ArrayList<>(numInputs);
        for (int i = 0; i < numInputs; ++i) {
            inputs.add(new PsbtInput());
        }

        // Init outputs
        int numOutputs = tx.getOutputs().size();
        outputs = new ArrayList<>(numOutputs);
        for (int i = 0; i < numOutputs; ++i) {
            outputs.add(new PsbtOutput());
        }

        unknown = new LinkedHashMap<>();
    }

    private PartiallySignedTransaction() {
        // Used by the parser
    }

    /**
     * Create a PSBT from a Base64 string
     *
     * @param psbtBase64 the encode PSBT
     * @return a parsed PSBT
     * @throws DecoderException  in case the PSBT string is not valid base64
     * @throws ProtocolException in case the PSBT is invalid
     */
    public static PartiallySignedTransaction fromBase64(String psbtBase64) throws ProtocolException {
        try {
            return PartiallySignedTransaction.read(ByteBuffer.wrap(Base64.decode(psbtBase64)));
        } catch (DecoderException e) {
            throw new ProtocolException("Could not decode Base64 PSBT", e);
        }
    }

    /**
     * Serialize this PSBT to a BASE64 format
     *
     * @return the serialized string
     */
    public String toBase64() {
        return Base64.toBase64String(write(ByteBuffer.allocate(messageSize())).array());
    }

    /**
     * Will create a copy of this transaction by serializing and deserializing without including a witness and setting
     * the internal serializer to not serialize witnesses. Additionally the input scriptSigs will be dropped.
     *
     * @param tx the tx to copy
     * @return a copy of the transaction
     */
    private static Transaction copyAsUnsignedTx(Transaction tx) {
        ByteBuffer buf = ByteBuffer.allocate(tx.messageSize());

        // Serialize the transaction without witness, then rewind the buffer and read it back
        tx.write(buf, false);
        buf.rewind();
        Transaction unsignedTx = Transaction.read(buf);

        // Clear script bytes from inputs
        List<TransactionInput> txInputs = unsignedTx.getInputs();
        for (int i = 0; i < txInputs.size(); i++) {
            unsignedTx.replaceInput(i, txInputs.get(i).withoutScriptBytes());
        }
        return unsignedTx;
    }

    /**
     * @return true is this PSBT is sane
     */
    public boolean isSane() {
        for (PsbtInput input : inputs) {
            if (!input.isSane()) return false;
        }
        return true;
    }

    /**
     * @return the final transaction or null if PSBT is incomplete
     */
    @Nullable
    public Transaction extract() {
        if (!isComplete()) return null;
        Transaction finalTx = tx.copy();
        // Set the input scripts & witness
        int numInputs = finalTx.getInputs().size();
        for (int i = 0; i < numInputs; i++) {
            // Add scriptSig and witness to input
            finalTx.replaceInput(i, finalTx.getInput(i)
                    .withScriptSig(inputs.get(i).finalScriptSig.copy())
                    .withWitness(inputs.get(i).finalScriptWitness.copy()));
        }
        return finalTx;
    }

    /**
     * @return true if this PSBT is complete
     */
    public boolean isComplete() {
        for (PsbtInput input : inputs) {
            // If this input is not final (scriptsig or scriptwitness), don't allow extracting
            if (!input.isComplete()) {
                return false;
            }
        }
        return true;
    }

    private void parseInputs(ByteBuffer payload) {
        int numInputs = tx.getInputs().size();
        inputs = new ArrayList<>(Math.min(numInputs, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (int i = 0; i < numInputs; i++) {
            inputs.add(PsbtInput.read(payload));
        }
        // Make sure that the number of inputs matches the number of inputs in the transaction
        if (inputs.size() != numInputs) {
            throw new ProtocolException("Inputs provided does not match the number of inputs in transaction.");
        }
    }

    private void parseOutputs(ByteBuffer payload) {
        int numOutputs = tx.getOutputs().size();
        outputs = new ArrayList<>(Math.min(numOutputs, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (int i = 0; i < numOutputs; i++) {
            outputs.add(PsbtOutput.read(payload));
        }
        // Make sure that the number of outputs matches the number of outputs in the transaction
        if (outputs.size() != numOutputs) {
            throw new ProtocolException("Outputs provided does not match the number of outputs in transaction.");
        }
    }

    /**
     * Deserialize a PSBT from a buffer
     *
     * @param payload the buffer
     * @return the PSBT
     * @throws ProtocolException for malformed PSBTs
     */
    public static PartiallySignedTransaction read(ByteBuffer payload) throws ProtocolException {
        byte[] magic = readBytes(payload, PSBT_MAGIC_BYTES.length);
        if (!Arrays.equals(PSBT_MAGIC_BYTES, magic)) {
            throw new ProtocolException("Invalid PSBT magic bytes");
        }

        PartiallySignedTransaction psbt = new PartiallySignedTransaction();

        psbt.unknown = new LinkedHashMap<>();

        // Used for duplicate key detection
        HashSet<RawBytes> keyLookup = new HashSet<>();

        // Read global data
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
                case PSBT_GLOBAL_UNSIGNED_TX:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, unsigned tx already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Global unsigned tx key is more than one byte type");
                    }
                    byte[] txBytes = readLengthPrefixedBytes(payload);
                    // Deserialize without witness as it is invalid to include a witness tx here
                    psbt.tx = Transaction.read(ByteBuffer.wrap(txBytes),
                            ProtocolVersion.CURRENT.intValue() | Transaction.SERIALIZE_TRANSACTION_NO_WITNESS);
                    // Make sure that all scriptSigs and scriptWitnesses are empty
                    for (TransactionInput input : psbt.tx.getInputs()) {
                        if (!input.getScriptSig().isEmpty() || !input.getWitness().isEmpty()) {
                            throw new ProtocolException(
                                    "Unsigned tx does not have empty scriptSigs and scriptWitnesses.");
                        }
                    }
                    break;
                // Unknown stuff
                default:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, key for unknown value already provided");
                    }
                    psbt.unknown.put(RawBytes.wrap(key), RawBytes.wrap(readLengthPrefixedBytes(payload)));
            }
        }

        if (!foundSeparator) {
            throw new ProtocolException("Separator is missing at the end of the global map");
        }

        // Make sure that we got an unsigned tx
        if (psbt.tx == null) {
            throw new ProtocolException("No unsigned transcation was provided");
        }

        // Read input data
        psbt.parseInputs(payload);

        // Read output data
        psbt.parseOutputs(payload);

        // Sanity check
        if (!psbt.isSane()) {
            throw new ProtocolException("PSBT is not sane.");
        }

        return psbt;
    }

    static void writeUnknown(ByteBuffer buf, Map<RawBytes, RawBytes> unknown) {
        // Write unknown things
        for (Map.Entry<RawBytes, RawBytes> entry : unknown.entrySet()) {
            writeLengthPrefixedBytes(buf, entry.getKey().getBytes());
            writeLengthPrefixedBytes(buf, entry.getValue().getBytes());
        }
    }

    static int sizeOfUnknown(Map<RawBytes, RawBytes> unknown) {
        return unknown.entrySet().stream().mapToInt(
                e -> {
                    int keyLen = e.getKey().getBytes().length;
                    int valueLen = e.getValue().getBytes().length;
                    return VarInt.sizeOf(keyLen) + keyLen + VarInt.sizeOf(valueLen) + valueLen;
                }).sum();
    }

    static void parseHDKeyPaths(ByteBuffer payload, byte[] key, Map<ECKey, KeyOriginInfo> hdKeyPaths) {
        // Make sure that the key is the size of pubkey + 1
        if (key.length != ECKey.PUBLIC_KEY_SIZE + 1 && key.length != ECKey.COMPRESSED_PUBLIC_KEY_SIZE + 1) {
            throw new ProtocolException("Size of key was not the expected size for the type BIP32 keypath");
        }
        // Read in the pubkey from key
        ECKey ecKey;
        try {
            ecKey = ECKey.fromPublicOnly(Arrays.copyOfRange(key, 1, key.length));
        } catch (IllegalArgumentException e) {
            throw new ProtocolException("Invalid pubkey", e);
        }
        if (hdKeyPaths.containsKey(ecKey)) {
            throw new ProtocolException("Duplicate Key, pubkey derivation path already provided");
        }

        // Read fingerprint and keypath
        byte[] value = readLengthPrefixedBytes(payload);
        int valueLen = value.length;

        if (valueLen % 4 != 0 || valueLen == 0) {
            throw new ProtocolException("Invalid length of HD key path");
        }

        // Parent fingerprint is 32 bit
        int parentFingerprint = ByteUtils.readInt32(ByteBuffer.wrap(value));
        // Read the rest of the data as the path
        ArrayList<ChildNumber> path = new ArrayList<>(valueLen / 4 - 1);
        for (int i = 4; i < valueLen; i += 4) {
            ChildNumber index = new ChildNumber((int) ByteUtils.readUint32(value, i));
            path.add(index);
        }
        hdKeyPaths.put(ecKey, new KeyOriginInfo(parentFingerprint, path));
    }

    static void serializeHDKeyPaths(ByteBuffer buf, Map<ECKey, KeyOriginInfo> hdkeypath, byte type) {
        for (Map.Entry<ECKey, KeyOriginInfo> entry : hdkeypath.entrySet()) {
            byte[] pubKey = entry.getKey().getPubKey();
            // Write the VarInt size of pubkey + type
            VarInt.of(pubKey.length + 1).write(buf);
            buf.put(type);
            buf.put(pubKey);

            // Write the VarInt size of the parentFingerprint + BIP32 path. Each element is 4 bytes (32bit)
            VarInt.of((entry.getValue().path.size() + 1) * 4L).write(buf);
            ByteUtils.writeInt32LE(entry.getValue().parentFingerprint, buf);
            for (ChildNumber path : entry.getValue().path) {
                ByteUtils.writeInt32LE(path.getI(), buf);
            }
        }
    }

    /**
     * Get the size of a path
     *
     * @param hdkeypath the path
     * @return the size in bytes
     */
    static int sizeOfHDKeyPaths(Map<ECKey, KeyOriginInfo> hdkeypath) {
        int size = 0;
        for (Map.Entry<ECKey, KeyOriginInfo> entry : hdkeypath.entrySet()) {
            // Size of type + pubkey
            int keyLen = entry.getKey().getPubKey().length + 1;
            // The total size is the varint of data plus the data
            size += VarInt.sizeOf(keyLen) + keyLen;

            // Size of parentFingerprint + BIP32 path. Each element is 4 bytes (32bit)
            int valueLen = (entry.getValue().path.size() + 1) * 4;
            // The total size is the varint of data plus the data
            size += VarInt.sizeOf(valueLen) + valueLen;

        }
        return size;
    }

    /**
     * @return the size of the serialized message.
     */
    public int messageSize() {
        // Magic bytes
        int size = PSBT_MAGIC_BYTES.length;
        // PSBT_GLOBAL_UNSIGNED_TX
        size += 2; // Key
        // Transaction
        int txSize = tx.messageSize(false);
        size += VarInt.sizeOf(txSize) + txSize;
        // Unknown
        size += sizeOfUnknown(unknown);
        // Separator
        size += 1;
        // Inputs and outputs
        size += inputs.stream().mapToInt(PsbtInput::messageSize).sum();
        size += outputs.stream().mapToInt(PsbtOutput::messageSize).sum();
        return size;
    }

    /**
     * Write this PSBT into the given buffer.
     * @param buf the buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the message doesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        // magic bytes
        buf.put(PSBT_MAGIC_BYTES);

        // unsigned tx flag
        buf.put((byte) 0x01).put(PSBT_GLOBAL_UNSIGNED_TX);

        // Write tx without a witness
        byte[] txBytes = tx.write(ByteBuffer.allocate(tx.messageSize()), false).array();
        writeLengthPrefixedBytes(buf, txBytes);

        writeUnknown(buf, unknown);

        // Separator
        buf.put(PSBT_SEPARATOR);

        // Write inputs
        for (PsbtInput input : inputs) {
            input.write(buf);
        }

        // Write outputs
        for (PsbtOutput output : outputs) {
            output.write(buf);
        }

        return buf;
    }

    /**
     * Merge a PSBT to this one. This action modifies this PSBT.
     *
     * @param other PSBT to merge to this one
     * @throws PsbtException.Mismatch when the PSBT transactions don't match
     */
    void mergeInto(PartiallySignedTransaction other) throws PsbtException.Mismatch {
        if (!tx.equals(other.tx)) {
            throw new PsbtException.Mismatch();
        }
        for (int i = 0; i < inputs.size(); ++i) {
            inputs.get(i).mergeInto(other.inputs.get(i));
        }
        for (int i = 0; i < outputs.size(); ++i) {
            outputs.get(i).mergeInto(other.outputs.get(i));
        }
        copyUnknown(other.unknown, unknown);
    }

    /**
     * Copy unknown key/values to a destination map
     *
     * @param from copy from this map
     * @param to   copy to this map
     */
    static void copyUnknown(Map<RawBytes, RawBytes> from, Map<RawBytes, RawBytes> to) {
        // Copy the unknown data
        for (Map.Entry<RawBytes, RawBytes> entry : from.entrySet()) {
            if (!to.containsKey(entry.getKey())) {
                to.put(entry.getKey().copy(), entry.getValue().copy());
            }
        }
    }

    /**
     * Combine a collection of PSBTs. The resulting PSBT is a copy and the original PSBTs are not affected
     *
     * @param psbts to combine
     * @return a new combined PSBT
     * @throws PsbtException in case of errors
     */
    public static PartiallySignedTransaction combine(Collection<PartiallySignedTransaction> psbts)
            throws PsbtException {
        Iterator<PartiallySignedTransaction> it = psbts.iterator();
        // If empty
        if (!it.hasNext()) {
            throw new PsbtException.Invalid("No PSBTs provided");
        }
        PartiallySignedTransaction first = it.next();
        // Make a deep copy of the first PSBT by serializing and deserializing
        ByteBuffer buf = first.write(ByteBuffer.allocate(first.messageSize()));
        buf.rewind();
        PartiallySignedTransaction mergedPsbt = PartiallySignedTransaction.read(buf);
        // Merge the rest of the PSBTs to the copied one
        while (it.hasNext()) {
            mergedPsbt.mergeInto(it.next());
        }

        if (!mergedPsbt.isSane()) {
            throw new PsbtException.Invalid("PSBT is not sane");
        }
        return mergedPsbt;
    }

    public static class KeyOriginInfo {
        public final int parentFingerprint;
        public final List<ChildNumber> path;

        public KeyOriginInfo(int parentFingerprint, List<ChildNumber> path) {
            this.parentFingerprint = parentFingerprint;
            this.path = ImmutableList.copyOf(path);
        }
    }

    public static class PsbtException extends Throwable {
        protected PsbtException(String msg) {
            super(msg);
        }

        protected PsbtException() {
            super();
        }

        public static class Invalid extends PsbtException {
            public Invalid(String msg) {
                super(msg);
            }
        }

        public static class Mismatch extends PsbtException {
        }
    }
}
