/**
 * Copyright 2011 Google Inc.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.*;

import static com.google.bitcoin.core.Utils.*;

/**
 * A transaction represents the movement of coins from some addresses to some other addresses. It can also represent
 * the minting of new coins. A Transaction object corresponds to the equivalent in the BitCoin C++ implementation.<p>
 *
 * It implements TWO serialization protocols - the BitCoin proprietary format which is identical to the C++
 * implementation and is used for reading/writing transactions to the wire and for hashing. It also implements Java
 * serialization which is used for the wallet. This allows us to easily add extra fields used for our own accounting
 * or UI purposes.
 */
public class Transaction extends Message implements Serializable {
    private static final long serialVersionUID = -8567546957352643140L;

    // These are serialized in both bitcoin and java serialization.
    long version;
    ArrayList<TransactionInput> inputs;
    ArrayList<TransactionOutput> outputs;
    long lockTime;

    // This is only stored in Java serialization. It records which blocks (and their height + work) the transaction
    // has been included in. For most transactions this set will have a single member. In the case of a chain split a
    // transaction may appear in multiple blocks but only one of them is part of the best chain. It's not valid to
    // have an identical transaction appear in two blocks in the same chain but this invariant is expensive to check,
    // so it's not directly enforced anywhere.
    //
    // If this transaction is not stored in the wallet, appearsIn is null.
    Set<StoredBlock> appearsIn;

    // This is an in memory helper only.
    transient Sha256Hash hash;

    Transaction(NetworkParameters params) {
        super(params);
        version = 1;
        inputs = new ArrayList<TransactionInput>();
        outputs = new ArrayList<TransactionOutput>();
        // We don't initialize appearsIn deliberately as it's only useful for transactions stored in the wallet.
    }

    /**
     * Creates a transaction from the given serialized bytes, eg, from a block or a tx network message.
     */
    public Transaction(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }

    /**
     * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
     */
    public Transaction(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
        // inputs/outputs will be created in parse()
    }

    /**
     * Returns a read-only list of the inputs of this transaction.
     */
    public List<TransactionInput> getInputs() {
        return Collections.unmodifiableList(inputs);
    }

    /**
     * Returns the transaction hash as you see them in the block explorer.
     */
    public Sha256Hash getHash() {
        if (hash == null) {
            byte[] bits = bitcoinSerialize();
            hash = new Sha256Hash(reverseBytes(doubleDigest(bits)));
        }
        return hash;
    }

    public String getHashAsString() {
        return getHash().toString();
    }

    void setFakeHashForTesting(Sha256Hash hash) {
        this.hash = hash;
    }

    /**
     * Calculates the sum of the outputs that are sending coins to a key in the wallet. The flag controls whether to
     * include spent outputs or not.
     */
    BigInteger getValueSentToMe(Wallet wallet, boolean includeSpent) {
        // This is tested in WalletTest.
        BigInteger v = BigInteger.ZERO;
        for (TransactionOutput o : outputs) {
            if (!o.isMine(wallet)) continue;
            if (!includeSpent && o.isSpent) continue;
            v = v.add(o.getValue());
        }
        return v;
    }

    /**
     * Calculates the sum of the outputs that are sending coins to a key in the wallet.
     */
    public BigInteger getValueSentToMe(Wallet wallet) {
        return getValueSentToMe(wallet, true);
    }

    /**
     * Returns a set of blocks which contain the transaction, or null if this transaction doesn't have that data
     * because it's not stored in the wallet or because it has never appeared in a block.
     */
    Set<StoredBlock> getAppearsIn() {
        return appearsIn;
    }

    /**
     * Adds the given block to the internal serializable set of blocks in which this transaction appears. This is
     * used by the wallet to ensure transactions that appear on side chains are recorded properly even though the
     * block stores do not save the transaction data at all.
     */
    void addBlockAppearance(StoredBlock block) {
        if (appearsIn == null) {
            appearsIn = new HashSet<StoredBlock>();
        }
        appearsIn.add(block);
    }

    /**
     * Calculates the sum of the inputs that are spending coins with keys in the wallet. This requires the
     * transactions sending coins to those keys to be in the wallet. This method will not attempt to download the
     * blocks containing the input transactions if the key is in the wallet but the transactions are not.
     *
     * @return sum in nanocoins.
     */
    public BigInteger getValueSentFromMe(Wallet wallet) throws ScriptException {
        // This is tested in WalletTest.
        BigInteger v = BigInteger.ZERO;
        for (TransactionInput input : inputs) {
            boolean connected = input.outpoint.connect(wallet.unspent.values()) ||
                                input.outpoint.connect(wallet.spent.values());
            if (connected) {
                // This input is taking value from an transaction in our wallet. To discover the value,
                // we must find the connected transaction.
                v = v.add(input.outpoint.getConnectedOutput().getValue());
            }
        }
        return v;
    }

    /**
     * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
     * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
     * 
     * In the official client, this enum also has another flag, SIGHASH_ANYONECANPAY. In this implementation,
     * that's kept separate. Only SIGHASH_ALL is actually used in the official client today. The other flags
     * exist to allow for distributed contracts.
     */
    public enum SigHash {
        ALL,         // 1
        NONE,        // 2
        SINGLE,      // 3
    }

    void parse() throws ProtocolException {
        version = readUint32();
        // First come the inputs.
        long numInputs = readVarInt();
        inputs = new ArrayList<TransactionInput>((int)numInputs);
        for (long i = 0; i < numInputs; i++) {
            TransactionInput input = new TransactionInput(params, bytes, cursor);
            inputs.add(input);
            cursor += input.getMessageSize();
        }
        // Now the outputs
        long numOutputs = readVarInt();
        outputs = new ArrayList<TransactionOutput>((int)numOutputs);
        for (long i = 0; i < numOutputs; i++) {
            TransactionOutput output = new TransactionOutput(params, this, bytes, cursor);
            outputs.add(output);
            cursor += output.getMessageSize();
        }
        lockTime = readUint32();
        
        // Store a hash, it may come in useful later (want to avoid reserialization costs).
        hash = new Sha256Hash(reverseBytes(doubleDigest(bytes, offset, cursor - offset)));
    }

    /**
     * A coinbase transaction is one that creates a new coin. They are the first transaction in each block and their
     * value is determined by a formula that all implementations of BitCoin share. In 2011 the value of a coinbase
     * transaction is 50 coins, but in future it will be less. A coinbase transaction is defined not only by its
     * position in a block but by the data in the inputs.
     */
    public boolean isCoinBase() {
        return inputs.get(0).isCoinBase();
    }

    /**
     * @return A human readable version of the transaction useful for debugging.
     */
    public String toString() {
        StringBuffer s = new StringBuffer();
        if (isCoinBase()) {
            String script = "???";
            String script2 = "???";
            try {
                script = inputs.get(0).getScriptSig().toString();
                script2 = outputs.get(0).getScriptPubKey().toString();
            } catch (ScriptException e) {}
            return "     == COINBASE TXN (scriptSig " + script + ")  (scriptPubKey " + script2 + ")";
        }
        for (TransactionInput in : inputs) {
            s.append("     ");
            s.append("from ");
            
            try {
                s.append(in.getScriptSig().getFromAddress().toString());
            } catch (Exception e) {
                s.append("[exception: ").append(e.getMessage()).append("]");
                throw new RuntimeException(e);
            }
            s.append("\n");
        }
        for (TransactionOutput out : outputs) {
            s.append("       ");
            s.append("to ");
            try {
                Address toAddr = new Address(params, out.getScriptPubKey().getPubKeyHash());
                s.append(toAddr.toString());
                s.append(" ");
                s.append(bitcoinValueToFriendlyString(out.getValue()));
                s.append(" BTC");
            } catch (Exception e) {
                s.append("[exception: ").append(e.getMessage()).append("]");
            }
            s.append("\n");
        }
        return s.toString();
    }

    /**
     * Adds an input to this transaction that imports value from the given output. Note that this input is NOT
     * complete and after every input is added with addInput() and every output is added with addOutput(),
     * signInputs() must be called to finalize the transaction and finish the inputs off. Otherwise it won't be
     * accepted by the network.
     */
    public void addInput(TransactionOutput from) {
        inputs.add(new TransactionInput(params, from));
    }

    /**
     * Adds the given output to this transaction. The output must be completely initialized.
     */
    public void addOutput(TransactionOutput to) {
        to.parentTransaction = this;
        outputs.add(to);
    }

    /**
     * Once a transaction has some inputs and outputs added, the signatures in the inputs can be calculated. The
     * signature is over the transaction itself, to prove the redeemer actually created that transaction,
     * so we have to do this step last.<p>
     *
     * This method is similar to SignatureHash in script.cpp
     *
     * @param hashType This should always be set to SigHash.ALL currently. Other types are unused.
     * @param wallet A wallet is required to fetch the keys needed for signing.
     */
    @SuppressWarnings({"SameParameterValue"})
    public void signInputs(SigHash hashType, Wallet wallet) throws ScriptException {
        assert inputs.size() > 0;
        assert outputs.size() > 0;

        // I don't currently have an easy way to test other modes work, as the official client does not use them.
        assert hashType == SigHash.ALL;

        // The transaction is signed with the input scripts empty except for the input we are signing. In the case
        // where addInput has been used to set up a new transaction, they are already all empty. The input being signed
        // has to have the connected OUTPUT program in it when the hash is calculated!
        //
        // Note that each input may be claiming an output sent to a different key. So we have to look at the outputs
        // to figure out which key to sign with.

        byte[][] signatures = new byte[inputs.size()][];
        ECKey[] signingKeys = new ECKey[inputs.size()];
        for (int i = 0; i < inputs.size(); i++) {
            TransactionInput input = inputs.get(i);
            assert input.scriptBytes.length == 0 : "Attempting to sign a non-fresh transaction";
            // Set the input to the script of its output.
            input.scriptBytes = input.outpoint.getConnectedPubKeyScript();
            // Find the signing key we'll need to use.
            byte[] connectedPubKeyHash = input.outpoint.getConnectedPubKeyHash();
            ECKey key = wallet.findKeyFromPubHash(connectedPubKeyHash);
            // This assert should never fire. If it does, it means the wallet is inconsistent.
            assert key != null : "Transaction exists in wallet that we cannot redeem: " + Utils.bytesToHexString(connectedPubKeyHash);
            // Keep the key around for the script creation step below.
            signingKeys[i] = key;
            // The anyoneCanPay feature isn't used at the moment.
            boolean anyoneCanPay = false;
            byte[] hash = hashTransactionForSignature(hashType, anyoneCanPay);
            Utils.LOG("  signInputs hash=" + Utils.bytesToHexString(hash));
            // Set the script to empty again for the next input.
            input.scriptBytes = TransactionInput.EMPTY_ARRAY;

            // Now sign for the output so we can redeem it. We use the keypair to sign the hash,
            // and then put the resulting signature in the script along with the public key (below).
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                bos.write(key.sign(hash));
                bos.write((hashType.ordinal() + 1) | (anyoneCanPay ? 0x80 : 0)) ;
                signatures[i] = bos.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
        }

        // Now we have calculated each signature, go through and create the scripts. Reminder: the script consists of
        // a signature (over a hash of the transaction) and the complete public key needed to sign for the connected
        // output.
        for (int i = 0; i < inputs.size(); i++) {
            TransactionInput input = inputs.get(i);
            assert input.scriptBytes.length == 0;
            ECKey key = signingKeys[i];
            input.scriptBytes = Script.createInputScript(signatures[i], key.getPubKey());
        }

        // Every input is now complete.
    }

    private byte[] hashTransactionForSignature(SigHash type, boolean anyoneCanPay) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bitcoinSerializeToStream(bos);
            // We also have to write a hash type.
            int hashType = type.ordinal() + 1;
            if (anyoneCanPay)
                hashType |= 0x80;
            Utils.uint32ToByteStreamLE(hashType, bos);
            // Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
            // however then we would expect that it is IS reversed.
            return doubleDigest(bos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Given a named input and the transaction output it connects to, runs the script formed from the
     * concatenation of the input and output scripts, returning true if the link is valid. In
     * this way, we prove that the creator of this transaction is allowed to redeem the output
     * of the connectedTx and thus spend the money.<p>
     *
     * <b>WARNING: NOT FINISHED</b><p>
     * 
     * @param inputIndex Which input to verify.
     * @param connectedTx The Transaction that the input is connected to.
     */
    @SuppressWarnings("unused")
    public boolean verifyInput(int inputIndex, Transaction connectedTx) throws ScriptException {
        TransactionInput input = inputs.get(inputIndex);
        //int outputIndex = (int) input.outpoint.index;
        //assert outputIndex >= 0 && outputIndex < connectedTx.outputs.size();
        //Script outScript = connectedTx.outputs.get(outputIndex).getScriptPubKey();
        Script inScript = input.getScriptSig();
        //Script script = Script.join(inScript, outScript);
        //if (script.run(this)) {
        //  LOG("Transaction input successfully verified!");
        //  return true;
        //}
        byte[] pubkey = inScript.getPubKey();

        return false;
    }
    
    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(version, stream);
        stream.write(new VarInt(inputs.size()).encode());
        for (TransactionInput in : inputs)
            in.bitcoinSerializeToStream(stream);
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput out : outputs)
            out.bitcoinSerializeToStream(stream);
        uint32ToByteStreamLE(lockTime, stream);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Transaction)) return false;
        Transaction t = (Transaction) other;

        return t.getHash().equals(getHash());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getHash().hash);
    }
}
