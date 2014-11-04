/**
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.core;

import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.ref.WeakReference;
import java.util.Arrays;

import static com.google.common.base.Preconditions.*;

/**
 * A TransactionOutput message contains a scriptPubKey that controls who is able to spend its value. It is a sub-part
 * of the Transaction message.
 */
public class TransactionOutput extends ChildMessage implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(TransactionOutput.class);
    private static final long serialVersionUID = -590332479859256824L;

    // The output's value is kept as a native type in order to save class instances.
    private long value;

    // A transaction output has a script used for authenticating that the redeemer is allowed to spend
    // this output.
    private byte[] scriptBytes;

    // The script bytes are parsed and turned into a Script on demand.
    private transient WeakReference<Script> scriptPubKey;

    // These fields are Java serialized but not Bitcoin serialized. They are used for tracking purposes in our wallet
    // only. If set to true, this output is counted towards our balance. If false and spentBy is null the tx output
    // was owned by us and was sent to somebody else. If false and spentBy is set it means this output was owned by
    // us and used in one of our own transactions (eg, because it is a change output).
    private boolean availableForSpending;
    @Nullable private TransactionInput spentBy;

    private transient int scriptLen;

    /**
     * Deserializes a transaction output message. This is usually part of a transaction message.
     */
    public TransactionOutput(NetworkParameters params, @Nullable Transaction parent, byte[] payload,
                             int offset) throws ProtocolException {
        super(params, payload, offset);
        setParent(parent);
        availableForSpending = true;
    }

    /**
     * Deserializes a transaction output message. This is usually part of a transaction message.
     *
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @throws ProtocolException
     */
    public TransactionOutput(NetworkParameters params, @Nullable Transaction parent, byte[] payload, int offset,
                             boolean parseLazy, boolean parseRetain) throws ProtocolException {
        super(params, payload, offset, parent, parseLazy, parseRetain, UNKNOWN_LENGTH);
        availableForSpending = true;
    }

    /**
     * Creates an output that sends 'value' to the given address (public key hash). The amount should be created with
     * something like {@link Utils#valueOf(int, int)}. Typically you would use
     * {@link Transaction#addOutput(Coin, Address)} instead of creating a TransactionOutput directly.
     */
    public TransactionOutput(NetworkParameters params, @Nullable Transaction parent, Coin value, Address to) {
        this(params, parent, value, ScriptBuilder.createOutputScript(to).getProgram());
    }

    /**
     * Creates an output that sends 'value' to the given public key using a simple CHECKSIG script (no addresses). The
     * amount should be created with something like {@link Utils#valueOf(int, int)}. Typically you would use
     * {@link Transaction#addOutput(Coin, ECKey)} instead of creating an output directly.
     */
    public TransactionOutput(NetworkParameters params, @Nullable Transaction parent, Coin value, ECKey to) {
        this(params, parent, value, ScriptBuilder.createOutputScript(to).getProgram());
    }

    public TransactionOutput(NetworkParameters params, @Nullable Transaction parent, Coin value, byte[] scriptBytes) {
        super(params);
        // Negative values obviously make no sense, except for -1 which is used as a sentinel value when calculating
        // SIGHASH_SINGLE signatures, so unfortunately we have to allow that here.
        checkArgument(value.signum() >= 0 || value.equals(Coin.NEGATIVE_SATOSHI), "Negative values not allowed");
        checkArgument(value.compareTo(NetworkParameters.MAX_MONEY) < 0, "Values larger than MAX_MONEY not allowed");
        this.value = value.value;
        this.scriptBytes = scriptBytes;
        setParent(parent);
        availableForSpending = true;
        length = 8 + VarInt.sizeOf(scriptBytes.length) + scriptBytes.length;
    }

    public Script getScriptPubKey() throws ScriptException {
        // Quick hack to try and reduce memory consumption on Androids. SoftReference is the same as WeakReference
        // on Dalvik (by design), so this arrangement just means that we can avoid the cost of re-parsing the script
        // bytes if getScriptPubKey is called multiple times in quick succession in between garbage collections.
        Script script = scriptPubKey == null ? null : scriptPubKey.get();
        if (script == null) {
            maybeParse();
            script = new Script(scriptBytes);
            scriptPubKey = new WeakReference<Script>(script);
            return script;
        }
        return script;
    }

    /**
     * <p>If the output script pays to an address as in <a href="https://bitcoin.org/en/developer-guide#term-p2pkh">
     * P2PKH</a>, return the address of the receiver, i.e., a base58 encoded hash of the public key in the script. </p>
     *
     * @param networkParameters needed to specify an address
     * @return null, if the output script is not the form <i>OP_DUP OP_HASH160 <PubkeyHash> OP_EQUALVERIFY OP_CHECKSIG</i>,
     * i.e., not P2PKH
     * @return an address made out of the public key hash
     */
    @Nullable
    public Address getAddressFromP2PKHScript(NetworkParameters networkParameters) throws ScriptException{
        if (getScriptPubKey().isSentToAddress())
            return getScriptPubKey().getToAddress(networkParameters);

        return null;
    }

    /**
     * <p>If the output script pays to a redeem script, return the address of the redeem script as described by,
     * i.e., a base58 encoding of [one-byte version][20-byte hash][4-byte checksum], where the 20-byte hash refers to
     * the redeem script.</p>
     *
     * <p>P2SH is described by <a href="https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki">BIP 16</a> and
     * <a href="https://bitcoin.org/en/developer-guide#p2sh-scripts">documented in the Bitcoin Developer Guide</a>.</p>
     *
     * @param networkParameters needed to specify an address
     * @return null if the output script does not pay to a script hash
     * @return an address that belongs to the redeem script
     */
    @Nullable
    public Address getAddressFromP2SH(NetworkParameters networkParameters) throws ScriptException{
        if (getScriptPubKey().isPayToScriptHash())
            return getScriptPubKey().getToAddress(networkParameters);

        return null;
    }

    @Override
    protected void parseLite() throws ProtocolException {
        value = readInt64();
        scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen;
    }

    @Override
    void parse() throws ProtocolException {
        scriptBytes = readBytes(scriptLen);
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        checkNotNull(scriptBytes);
        maybeParse();
        Utils.int64ToByteStreamLE(value, stream);
        // TODO: Move script serialization into the Script class, where it belongs.
        stream.write(new VarInt(scriptBytes.length).encode());
        stream.write(scriptBytes);
    }

    /**
     * Returns the value of this output. This is the amount of currency that the destination address
     * receives.
     */
    public Coin getValue() {
        maybeParse();
        try {
            return Coin.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    /**
     * Sets the value of this output.
     */
    public void setValue(Coin value) {
        checkNotNull(value);
        unCache();
        this.value = value.value;
    }

    /**
     * Gets the index of this output in the parent transaction, or throws if this output is free standing. Iterates
     * over the parents list to discover this.
     */
    public int getIndex() {
        for (int i = 0; i < getParentTransaction().getOutputs().size(); i++) {
            if (getParentTransaction().getOutputs().get(i) == this)
                return i;
        }
        throw new IllegalStateException("Output linked to wrong parent transaction?");
    }

    /**
     * <p>Gets the minimum value for a txout of this size to be considered non-dust by a reference client
     * (and thus relayed). See: CTxOut::IsDust() in the reference client. The assumption is that any output that would
     * consume more than a third of its value in fees is not something the Bitcoin system wants to deal with right now,
     * so we call them "dust outputs" and they're made non standard. The choice of one third is somewhat arbitrary and
     * may change in future.</p>
     *
     * <p>You probably should use {@link org.bitcoinj.core.TransactionOutput#getMinNonDustValue()} which uses
     * a safe fee-per-kb by default.</p>
     *
     * @param feePerKbRequired The fee required per kilobyte. Note that this is the same as the reference client's -minrelaytxfee * 3
     *                         If you want a safe default, use {@link Transaction#REFERENCE_DEFAULT_MIN_TX_FEE}*3
     */
    public Coin getMinNonDustValue(Coin feePerKbRequired) {
        // A typical output is 33 bytes (pubkey hash + opcodes) and requires an input of 148 bytes to spend so we add
        // that together to find out the total amount of data used to transfer this amount of value. Note that this
        // formula is wrong for anything that's not a pay-to-address output, unfortunately, we must follow the reference
        // clients wrongness in order to ensure we're considered standard. A better formula would either estimate the
        // size of data needed to satisfy all different script types, or just hard code 33 below.
        final long size = this.bitcoinSerialize().length + 148;
        Coin[] nonDustAndRemainder = feePerKbRequired.multiply(size).divideAndRemainder(1000);
        return nonDustAndRemainder[1].equals(Coin.ZERO) ? nonDustAndRemainder[0] : nonDustAndRemainder[0].add(Coin.SATOSHI);
    }

    /**
     * Returns the minimum value for this output to be considered "not dust", i.e. the transaction will be relayable
     * and mined by default miners. For normal pay to address outputs, this is 546 satoshis, the same as
     * {@link Transaction#MIN_NONDUST_OUTPUT}.
     */
    public Coin getMinNonDustValue() {
        return getMinNonDustValue(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(3));
    }

    /**
     * Sets this objects availableForSpending flag to false and the spentBy pointer to the given input.
     * If the input is null, it means this output was signed over to somebody else rather than one of our own keys.
     * @throws IllegalStateException if the transaction was already marked as spent.
     */
    public void markAsSpent(TransactionInput input) {
        checkState(availableForSpending);
        availableForSpending = false;
        spentBy = input;
        if (parent != null)
            if (log.isDebugEnabled()) log.debug("Marked {}:{} as spent by {}", getParentTransaction().getHash(), getIndex(), input);
        else
            if (log.isDebugEnabled()) log.debug("Marked floating output as spent by {}", input);
    }

    /**
     * Resets the spent pointer / availableForSpending flag to null.
     */
    public void markAsUnspent() {
        if (parent != null)
            if (log.isDebugEnabled()) log.debug("Un-marked {}:{} as spent by {}", getParentTransaction().getHash(), getIndex(), spentBy);
        else
            if (log.isDebugEnabled()) log.debug("Un-marked floating output as spent by {}", spentBy);
        availableForSpending = true;
        spentBy = null;
    }

    /**
     * Returns whether {@link TransactionOutput#markAsSpent(TransactionInput)} has been called on this class. A
     * {@link Wallet} will mark a transaction output as spent once it sees a transaction input that is connected to it.
     * Note that this flag can be false when an output has in fact been spent according to the rest of the network if
     * the spending transaction wasn't downloaded yet, and it can be marked as spent when in reality the rest of the
     * network believes it to be unspent if the signature or script connecting to it was not actually valid.
     */
    public boolean isAvailableForSpending() {
        return availableForSpending;
    }

    /**
     * The backing script bytes which can be turned into a Script object.
     * @return the scriptBytes
    */
    public byte[] getScriptBytes() {
        maybeParse();
        return scriptBytes;
    }

    /**
     * Returns true if this output is to a key in the wallet or to an address/script we are watching.
     */
    public boolean isMineOrWatched(TransactionBag transactionBag) {
        return isMine(transactionBag) || isWatched(transactionBag);
    }

    /**
     * Returns true if this output is to a key, or an address we have the keys for, in the wallet.
     */
    public boolean isWatched(TransactionBag transactionBag) {
        try {
            Script script = getScriptPubKey();
            return transactionBag.isWatchedScript(script);
        } catch (ScriptException e) {
            // Just means we didn't understand the output of this transaction: ignore it.
            log.debug("Could not parse tx output script: {}", e.toString());
            return false;
        }
    }

    /**
     * Returns true if this output is to a key, or an address we have the keys for, in the wallet.
     */
    public boolean isMine(TransactionBag transactionBag) {
        try {
            Script script = getScriptPubKey();
            if (script.isSentToRawPubKey()) {
                byte[] pubkey = script.getPubKey();
                return transactionBag.isPubKeyMine(pubkey);
            } if (script.isPayToScriptHash()) {
                return transactionBag.isPayToScriptHashMine(script.getPubKeyHash());
            } else {
                byte[] pubkeyHash = script.getPubKeyHash();
                return transactionBag.isPubKeyHashMine(pubkeyHash);
            }
        } catch (ScriptException e) {
            // Just means we didn't understand the output of this transaction: ignore it.
            log.debug("Could not parse tx output script: {}", e.toString());
            return false;
        }
    }

    /**
     * Returns a human readable debug string.
     */
    @Override
    public String toString() {
        try {
            Script script = getScriptPubKey();
            StringBuilder buf = new StringBuilder("TxOut of ");
            buf.append(Coin.valueOf(value).toFriendlyString());
            if (script.isSentToAddress() || script.isPayToScriptHash())
                buf.append(" to ").append(script.getToAddress(params));
            else if (script.isSentToRawPubKey())
                buf.append(" to pubkey ").append(Utils.HEX.encode(script.getPubKey()));
            else if (script.isSentToMultiSig())
                buf.append(" to multisig");
            else
                buf.append(" (unknown type)");
            buf.append(" script:");
            buf.append(script);
            return buf.toString();
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns the connected input.
     */
    @Nullable
    public TransactionInput getSpentBy() {
        return spentBy;
    }

    /**
     * Returns the transaction that owns this output, or throws NullPointerException if unowned.
     */
    public Transaction getParentTransaction() {
        return checkNotNull((Transaction) parent, "Free-standing TransactionOutput");
    }

    /**
     * Ensure object is fully parsed before invoking java serialization.  The backing byte array
     * is transient so if the object has parseLazy = true and hasn't invoked checkParse yet
     * then data will be lost during serialization.
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        maybeParse();
        out.defaultWriteObject();
    }

    /**
     * Returns a new {@link TransactionOutPoint}, which is essentially a structure pointing to this output.
     * Requires that this output is not detached.
     */
    public TransactionOutPoint getOutPointFor() {
        return new TransactionOutPoint(params, getIndex(), getParentTransaction());
    }

    /** Returns a copy of the output detached from its containing transaction, if need be. */
    public TransactionOutput duplicateDetached() {
        return new TransactionOutput(params, null, Coin.valueOf(value), org.spongycastle.util.Arrays.clone(scriptBytes));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TransactionOutput other = (TransactionOutput) o;

        if (!Arrays.equals(scriptBytes, other.scriptBytes)) return false;
        if (value != other.value) return false;
        if (parent != null && parent != other.parent) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return 31 * (int) value + (scriptBytes != null ? Arrays.hashCode(scriptBytes) : 0);
    }
}
