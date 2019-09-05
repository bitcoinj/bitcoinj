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
import com.google.common.collect.ImmutableList;
import org.bitcoinj.crypto.ChildNumber;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.*;

import static org.bitcoinj.core.Transaction.SERIALIZE_TRANSACTION_NO_WITNESS;

/**
 * A class that implements the BIP-174 spec "Partially Signed Bitcoin Transaction Format"
 * https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
 *
 * Note: this is an experimental "beta" API and could change in future releases
 * */
@Beta
public class PartiallySignedTransaction extends ChildMessage {
    //// PSBT Constants
    // Magic bytes
    final static byte[] PSBT_MAGIC_BYTES = {'p', 's', 'b', 't', (byte) 0xff};
    // Global types
    final static byte PSBT_GLOBAL_UNSIGNED_TX = 0x00;
    // Input types
    final static byte PSBT_IN_NON_WITNESS_UTXO = 0x00;
    final static byte PSBT_IN_WITNESS_UTXO = 0x01;
    final static byte PSBT_IN_PARTIAL_SIG = 0x02;
    final static byte PSBT_IN_SIGHASH = 0x03;
    final static byte PSBT_IN_REDEEMSCRIPT = 0x04;
    final static byte PSBT_IN_WITNESSSCRIPT = 0x05;
    final static byte PSBT_IN_BIP32_DERIVATION = 0x06;
    final static byte PSBT_IN_SCRIPTSIG = 0x07;
    final static byte PSBT_IN_SCRIPTWITNESS = 0x08;
    // Output types
    final static byte PSBT_OUT_REDEEMSCRIPT = 0x00;
    final static byte PSBT_OUT_WITNESSSCRIPT = 0x01;
    final static byte PSBT_OUT_BIP32_DERIVATION = 0x02;
    // The separator is 0x00. Reading this in means that the unserializer can interpret it
    // as a 0 length key which indicates that this is the separator. The separator has no value.
    final static byte PSBT_SEPARATOR = 0x00;

    public Transaction tx;
    public ArrayList<PSBTInput> inputs;
    public ArrayList<PSBTOutput> outputs;
    public Map<RawBytes, RawBytes> unknown;

    public PartiallySignedTransaction(Transaction unsignedTx) {
        super(unsignedTx.params);

        // The PSBT tx must not serialize witnesses, so drop them if needed
        tx = copyAsUnsignedTx(unsignedTx);

        // Init inputs
        int numInputs = tx.getInputs().size();
        inputs = new ArrayList<>(numInputs);
        for (int i = 0; i < numInputs; ++i) {
            inputs.add(new PSBTInput(params));
        }

        // Init outputs
        int numOutputs = tx.getOutputs().size();
        outputs = new ArrayList<>(numOutputs);
        for (int i = 0; i < numOutputs; ++i) {
            outputs.add(new PSBTOutput(params));
        }

        unknown = new LinkedHashMap<>();
    }

    public PartiallySignedTransaction(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
        // the properties will be initialized by the parser...
    }

    /**
     * Create a PSBT from a Base64 string
     *
     * @param params     the network parameters
     * @param psbtBase64 the encode PSBT
     * @return a parsed PSBT
     * @throws DecoderException  in case the PSBT string is not valid base64
     * @throws ProtocolException in case the PSBT is invalid
     */
    public static PartiallySignedTransaction fromBase64(NetworkParameters params, String psbtBase64) {
        return new PartiallySignedTransaction(params, Base64.decode(psbtBase64));
    }

    /**
     * Serialize this PSBT to a BASE64 format
     * @return the serialized string
     */
    public String toBase64() {
        return Base64.toBase64String(bitcoinSerialize());
    }

    /**
     * Will create a copy of this transaction by serializing and deserializing without including a witness and setting
     * the internal serializer to not serialize witnesses. Additionally the input scriptSigs will be dropped.
     * @param tx the tx to copy
     * @return a copy of the transaction
     */
    private static Transaction copyAsUnsignedTx(Transaction tx) {
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(tx.length < 32 ? 32 : tx.length + 32);
        try {
            tx.bitcoinSerializeToStream(stream, false);
        } catch (IOException ignored) {}
        Transaction unsignedTx = deserializeNoWitness(tx.serializer, stream.toByteArray());
        for (TransactionInput input : unsignedTx.getInputs()) {
            input.clearScriptBytes();
        }
        return unsignedTx;
    }

    /**
     * Parse a transaction with a no-witness serializer
     * @param baseSerializer the base serializer
     * @param bytes the transaction bytes
     * @return the parsed transaction
     */
    private static Transaction deserializeNoWitness(MessageSerializer baseSerializer, byte[] bytes) {
        // Create a no witness serializer and re-parse the serialized tx
        return baseSerializer.withProtocolVersionFlag(SERIALIZE_TRANSACTION_NO_WITNESS, true).makeTransaction(bytes);
    }

    /**
     * @return true is this PSBT is sane
     */
    public boolean isSane() {
        for (PSBTInput input : inputs) {
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
        // Restore a serializer with SegWit available
        finalTx.setSerializer(finalTx.serializer.withProtocolVersionFlag(SERIALIZE_TRANSACTION_NO_WITNESS, false));
        // Set the input scripts & witness
        int numInputs = finalTx.getInputs().size();
        for (int i = 0; i < numInputs; i++) {
            finalTx.getInput(i).setScriptSig(inputs.get(i).finalScriptSig.copy());
            finalTx.getInput(i).setWitness(inputs.get(i).finalScriptWitness.copy());
        }
        return finalTx;
    }

    /**
     * @return true if this PSBT is complete
     */
    public boolean isComplete() {
        for (PSBTInput input : inputs) {
            // If this input is not final (scriptsig or scriptwitness), don't allow extracting
            if (!input.isComplete()) {
                return false;
            }
        }
        return true;
    }

    private void parseInputs() {
        int totalInputs = tx.getInputs().size();
        inputs = new ArrayList<>(totalInputs);
        int i = 0;
        while (hasMoreBytes() && i < totalInputs) {
            PSBTInput input = new PSBTInput(params, this, payload, cursor, serializer);
            inputs.add(input);
            cursor += input.length;
            ++i;
        }
        // Make sure that the number of inputs matches the number of inputs in the transaction
        if (inputs.size() != totalInputs) {
            throw new ProtocolException("Inputs provided does not match the number of inputs in transaction.");
        }
    }

    private void parseOutputs() {
        int totalOutputs = tx.getOutputs().size();
        outputs = new ArrayList<>(totalOutputs);
        int i = 0;
        while (hasMoreBytes() && i < totalOutputs) {
            PSBTOutput output = new PSBTOutput(params, this, payload, cursor, serializer);
            outputs.add(output);
            cursor += output.length;
            ++i;
        }
        // Make sure that the number of outputs matches the number of outputs in the transaction
        if (outputs.size() != totalOutputs) {
            throw new ProtocolException("Outputs provided does not match the number of outputs in transaction.");
        }
    }

    @Override
    protected void parse() throws ProtocolException {
        byte[] magic = readBytes(PSBT_MAGIC_BYTES.length);
        if (!Arrays.equals(PSBT_MAGIC_BYTES, magic)) {
            throw new ProtocolException("Invalid PSBT magic bytes");
        }

        unknown = new LinkedHashMap<>();

        // Used for duplicate key detection
        HashSet<RawBytes> keyLookup = new HashSet<>();

        // Read global data
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
                case PSBT_GLOBAL_UNSIGNED_TX:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, unsigned tx already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Global unsigned tx key is more than one byte type");
                    }
                    byte[] txBytes = readByteArray();
                    // Deserialize without witness as it is invalid to include a witness tx here
                    tx = deserializeNoWitness(serializer, txBytes);
                    // Make sure that all scriptSigs and scriptWitnesses are empty
                    for (TransactionInput input : tx.getInputs()) {
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
                    unknown.put(RawBytes.wrap(key), RawBytes.wrap(readByteArray()));
            }
        }

        if (!foundSeparator) {
            throw new ProtocolException("Separator is missing at the end of the global map");
        }

        // Make sure that we got an unsigned tx
        if (tx == null) {
            throw new ProtocolException("No unsigned transcation was provided");
        }

        // Read input data
        parseInputs();

        // Read output data
        parseOutputs();

        // The total length of the PSBT
        length = cursor - offset;

        // Sanity check
        if (!isSane()) {
            throw new ProtocolException("PSBT is not sane.");
        }
    }

    static void serializeUnknown(OutputStream stream, Map<RawBytes, RawBytes> unknown) throws IOException {
        // Write unknown things
        for (Map.Entry<RawBytes, RawBytes> entry : unknown.entrySet()) {
            serializeToVector(stream, entry.getKey().getBytes());
            serializeToVector(stream, entry.getValue().getBytes());
        }
    }

    static void parseHDKeyPaths(Message msg, byte[] key, Map<ECKey, KeyOriginInfo> hdKeyPaths) {
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
        byte[] value = msg.readByteArray();
        int valueLen = value.length;

        if (valueLen % 4 != 0 || valueLen == 0) {
            throw new ProtocolException("Invalid length of HD key path");
        }

        // Parent fingerprint is 32 bit
        int parentFingerprint = (int) Utils.readUint32(value, 0);
        // Read the rest of the data as the path
        ArrayList<ChildNumber> path = new ArrayList<>(valueLen / 4 - 1);
        for (int i = 4; i < valueLen; i += 4) {
            ChildNumber index = new ChildNumber((int) Utils.readUint32(value, i));
            path.add(index);
        }
        hdKeyPaths.put(ecKey, new KeyOriginInfo(parentFingerprint, path));
    }

    static void serializeHDKeyPaths(OutputStream s, Map<ECKey, KeyOriginInfo> hdkeypath, byte type) throws IOException {
        for (Map.Entry<ECKey, KeyOriginInfo> entry : hdkeypath.entrySet()) {
            byte[] pubKey = entry.getKey().getPubKey();
            // Write the VarInt size of pubkey + type
            s.write(new VarInt(pubKey.length + 1).encode());
            s.write(type);
            s.write(pubKey);

            // Write the VarInt size of the parentFingerprint + BIP32 path. Each element is 4 bytes (32bit)
            s.write(new VarInt((entry.getValue().path.size() + 1) * 4).encode());
            Utils.uint32ToByteStreamLE(entry.getValue().parentFingerprint, s);
            for (ChildNumber path : entry.getValue().path) {
                Utils.uint32ToByteStreamLE(path.getI(), s);
            }
        }
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        // magic bytes
        stream.write(PSBT_MAGIC_BYTES);

        // unsigned tx flag
        serializeToVector(stream, PSBT_GLOBAL_UNSIGNED_TX);

        // Write serialized not witness tx to a stream
        tx.setSerializer(tx.serializer.withProtocolVersionFlag(SERIALIZE_TRANSACTION_NO_WITNESS, true));
        serializeToVector(stream, tx.bitcoinSerialize());

        serializeUnknown(stream, unknown);

        // Separator
        stream.write(PSBT_SEPARATOR);

        // Write inputs
        for (PSBTInput input : inputs) {
            input.bitcoinSerializeToStream(stream);
        }

        // Write outputs
        for (PSBTOutput output : outputs) {
            output.bitcoinSerializeToStream(stream);
        }
    }

    static void serializeToVector(OutputStream stream, byte value) throws IOException {
        stream.write(0x01); // the next field has size of 1 byte
        stream.write(value);
    }

    static void serializeToVector(OutputStream stream, byte[] value) throws IOException {
        stream.write(new VarInt(value.length).encode());
        stream.write(value);
    }

    /**
     * Merge a PSBT to this one.
     * @param other PSBT to merge to this one
     * @throws PsbtException.Mismatch when the PSBT transactions don't match
     */
    public void merge(PartiallySignedTransaction other) throws PsbtException.Mismatch {
        if (!tx.equals(other.tx)) {
            throw new PsbtException.Mismatch();
        }
        for (int i = 0; i < inputs.size(); ++i) {
            inputs.get(i).merge(other.inputs.get(i));
        }
        for (int i = 0; i < outputs.size(); ++i) {
            outputs.get(i).merge(other.outputs.get(i));
        }
        copyUnknown(other.unknown, unknown);
    }

    /**
     * Copy unknown key/values to a destination map
     * @param from copy from this map
     * @param to copy to this map
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
        // Make a deep copy of the first PSBT
        PartiallySignedTransaction mergedPsbt =
                new PartiallySignedTransaction(first.getParams(), first.bitcoinSerialize());
        // Merge the rest of the PSBTs to the copied one
        while (it.hasNext()) {
            mergedPsbt.merge(it.next());
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
