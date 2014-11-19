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

package org.bitcoinj.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;

/**
 * A UTXO message contains the information necessary to check a spending transaction.
 * It avoids having to store the entire parentTransaction just to get the hash and index.
 * Useful when working with free standing outputs.
 */
public class UTXO implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(UTXO.class);
    private static final long serialVersionUID = -8744924157056340509L;

    /**
     *  A transaction output has some value and a script used for authenticating that the redeemer is allowed to spend
     *  this output.
     */
    private Coin value;
    private byte[] scriptBytes;

    /** Hash of the transaction to which we refer. */
    private Sha256Hash hash;
    /** Which output of that transaction we are talking about. */
    private long index;
    /** The height of the tx of this output */
    private int height;
    /** If this output is from a coinbase tx */
    private boolean coinbase;
    /** The address of this output */
    private String address;
    /** The type of this address */
    private int addressType;

    /**
     * Creates a stored transaction output.
     * @param hash The hash of the containing transaction.
     * @param index The outpoint.
     * @param value The value available.
     * @param height The height this output was created in.
     * @param coinbase The coinbase flag.
     * @param scriptBytes The script bytes.
     */
    public UTXO(Sha256Hash hash,
                long index,
                Coin value,
                int height,
                boolean coinbase,
                byte[] scriptBytes) {
        this.hash = hash;
        this.index = index;
        this.value = value;
        this.height = height;
        this.scriptBytes = scriptBytes;
        this.coinbase = coinbase;
        this.address = "";
        this.addressType = 0;
    }

    /**
     * Creates a stored transaction output.
     * @param hash The hash of the containing transaction.
     * @param index The outpoint.
     * @param value The value available.
     * @param height The height this output was created in.
     * @param coinbase The coinbase flag.
     * @param scriptBytes The script bytes.
     * @param address The address.
     * @param addressType The address type.
     */
    public UTXO(Sha256Hash hash,
                long index,
                Coin value,
                int height,
                boolean coinbase,
                byte[] scriptBytes,
                String address,
                int addressType) {
        this(hash, index, value, height, coinbase, scriptBytes);
        this.address = address;
        this.addressType = addressType;
    }

    public UTXO(InputStream in) throws IOException {
        byte[] valueBytes = new byte[8];
        if (in.read(valueBytes, 0, 8) != 8)
            throw new EOFException();
        value = Coin.valueOf(Utils.readInt64(valueBytes, 0));

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

        byte[] coinbaseByte = new byte[1];
        in.read(coinbaseByte);
        if (coinbaseByte[0] == 1) {
            coinbase = true;
        } else {
            coinbase = false;
        }
    }

    /**
     * The value which this Transaction output holds.
     * @return the value.
     */
    public Coin getValue() {
        return value;
    }

    /**
     * The backing script bytes which can be turned into a Script object.
     * @return the scriptBytes.
     */
    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    /**
     * The hash of the transaction which holds this output.
     * @return the hash.
     */
    public Sha256Hash getHash() {
        return hash;
    }

    /**
     * The index of this output in the transaction which holds it.
     * @return the index.
     */
    public long getIndex() {
        return index;
    }

    /**
     * Gets the height of the block that created this output.
     * @return The height.
     */
    public int getHeight() {
        return height;
    }

    /**
     * Gets the flag of whether this was created by a coinbase tx.
     * @return The coinbase flag.
     */
    public boolean isCoinbase() {
        return coinbase;
    }

    /**
     * The address of this output.
     * @return The address.
     */
    public String getAddress() {
       return address;
    }

    /**
     * The type of the address.
     * @return The address type.
     */
    public int getAddressType() {
        return addressType;
    }

    @Override
    public String toString() {
        return String.format("Stored TxOut of %s (%s:%d)", value.toFriendlyString(), hash.toString(), index);
    }

    @Override
    public int hashCode() {
        return hash.hashCode() + (int)index;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UTXO other = (UTXO) o;
        return getHash().equals(other.getHash()) &&
                getIndex() == other.getIndex();
    }

    public void serializeToStream(OutputStream bos) throws IOException {
        Utils.uint64ToByteStreamLE(BigInteger.valueOf(value.value), bos);

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

        byte[] coinbaseByte = new byte[1];
        if(coinbase) {
            coinbaseByte[0] = 1;
        } else {
            coinbaseByte[0] = 0;
        }
        bos.write(coinbaseByte);
    }
}