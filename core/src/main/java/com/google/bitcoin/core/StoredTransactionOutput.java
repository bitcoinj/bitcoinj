/**
 * Copyright 2012 Matt Corallo.
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

import java.io.*;
import java.math.BigInteger;

/**
 * A StoredTransactionOutput message contains the information necessary to check a spending transaction.
 * It avoids having to store the entire parentTransaction just to get the hash and index.
 * Its only really useful for MemoryFullPrunedBlockStore, and should probably be moved there
 */
public class StoredTransactionOutput implements Serializable {
    private static final long serialVersionUID = -8744924157056340509L;

    /**
     *  A transaction output has some value and a script used for authenticating that the redeemer is allowed to spend
     *  this output.
     */
    private BigInteger value;
    private byte[] scriptBytes;

    /** Hash of the transaction to which we refer. */
    private Sha256Hash hash;
    /** Which output of that transaction we are talking about. */
    private long index;

    /** arbitrary value lower than -{@link NetworkParameters#spendableCoinbaseDepth}
     * (not too low to get overflows when we do blockHeight - NONCOINBASE_HEIGHT, though) */
    private static final int NONCOINBASE_HEIGHT = -200;
    /** The height of the creating block (for coinbases, NONCOINBASE_HEIGHT otherwise) */
    private int height;

    /**
     * Creates a stored transaction output
     * @param hash the hash of the containing transaction
     * @param index the outpoint
     * @param value the value available
     * @param height the height this output was created in
     * @param scriptBytes
     */
    public StoredTransactionOutput(Sha256Hash hash, long index, BigInteger value, int height, boolean isCoinbase, byte[] scriptBytes) {
        this.hash = hash;
        this.index = index;
        this.value = value;
        this.height = isCoinbase ? height : NONCOINBASE_HEIGHT;
        this.scriptBytes = scriptBytes;
    }

    public StoredTransactionOutput(Sha256Hash hash, TransactionOutput out, int height, boolean isCoinbase) {
        this.hash = hash;
        this.index = out.getIndex();
        this.value = out.getValue();
        this.height = isCoinbase ? height : NONCOINBASE_HEIGHT;
        this.scriptBytes = out.getScriptBytes();
    }

    public StoredTransactionOutput(InputStream in) throws IOException {
        byte[] valueBytes = new byte[8];
        if (in.read(valueBytes, 0, 8) != 8)
            throw new EOFException();
        value = BigInteger.valueOf(Utils.readInt64(valueBytes, 0));
        
        int scriptBytesLength = ((in.read() & 0xFF) << 0) |
                                ((in.read() & 0xFF) << 8) |
                                ((in.read() & 0xFF) << 16) |
                                ((in.read() & 0xFF) << 24);
        scriptBytes = new byte[scriptBytesLength];
        if (in.read(scriptBytes) != scriptBytesLength)
            throw new EOFException();
        
        byte[] hashBytes = new byte[32];
        if (in.read(hashBytes) != 32)
            throw new EOFException();
        hash = new Sha256Hash(hashBytes);
        
        byte[] indexBytes = new byte[4];
        if (in.read(indexBytes) != 4)
            throw new EOFException();
        index = Utils.readUint32(indexBytes, 0);

        height = ((in.read() & 0xFF) << 0) |
                 ((in.read() & 0xFF) << 8) |
                 ((in.read() & 0xFF) << 16) |
                 ((in.read() & 0xFF) << 24);
    }

    /**
     * The value which this Transaction output holds
     * @return the value
     */
    public BigInteger getValue() {
        return value;
    }

    /**
     * The backing script bytes which can be turned into a Script object.
     * @return the scriptBytes
     */
    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    /**
     * The hash of the transaction which holds this output
     * @return the hash
     */
    public Sha256Hash getHash() {
        return hash;
    }

    /**
     * The index of this output in the transaction which holds it
     * @return the index
     */
    public long getIndex() {
        return index;
    }

    /**
     * Gets the height of the block that created this output (or -1 if this output was not created by a coinbase)
     */
    public int getHeight() {
        return height;
    }

    public String toString() {
        return String.format("Stored TxOut of %s (%s:%d)", Utils.bitcoinValueToFriendlyString(value), hash.toString(), index);
    }

    public int hashCode() {
        return hash.hashCode() + (int)index;
    }

    public boolean equals(Object o) {
        if (!(o instanceof StoredTransactionOutput)) return false;
        return ((StoredTransactionOutput) o).getIndex() == this.getIndex() &&
                ((StoredTransactionOutput) o).getHash().equals(this.getHash());
    }

    public void serializeToStream(OutputStream bos) throws IOException {
        Utils.uint64ToByteStreamLE(value, bos);
        
        bos.write(0xFF & scriptBytes.length >> 0);
        bos.write(0xFF & scriptBytes.length >> 8);
        bos.write(0xFF & (scriptBytes.length >> 16));
        bos.write(0xFF & (scriptBytes.length >> 24));
        bos.write(scriptBytes);
        
        bos.write(hash.getBytes());
        Utils.uint32ToByteStreamLE(index, bos);
        
        bos.write(0xFF & (height >> 0));
        bos.write(0xFF & (height >> 8));
        bos.write(0xFF & (height >> 16));
        bos.write(0xFF & (height >> 24));
    }
}