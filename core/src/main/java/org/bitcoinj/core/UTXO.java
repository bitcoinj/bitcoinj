/*
 * Copyright 2012 Matt Corallo.
 * Copyright 2021 Andreas Schildbach
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

import org.bitcoinj.script.*;

import java.io.*;
import java.math.*;
import java.util.Locale;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;

// TODO: Fix this class: should not talk about addresses, height should be optional/support mempool height etc

/**
 * A UTXO message contains the information necessary to check a spending transaction.
 * It avoids having to store the entire parentTransaction just to get the hash and index.
 * Useful when working with free standing outputs.
 */
public class UTXO {
    private final Coin value;
    private final Script script;
    private final Sha256Hash hash;
    private final long index;
    private final int height;
    private final boolean coinbase;
    private final String address;

    /**
     * Creates a stored transaction output.
     *
     * @param hash     The hash of the containing transaction.
     * @param index    The outpoint.
     * @param value    The value available.
     * @param height   The height this output was created in.
     * @param coinbase The coinbase flag.
     */
    public UTXO(Sha256Hash hash,
                long index,
                Coin value,
                int height,
                boolean coinbase,
                Script script) {
        this(hash, index, value, height, coinbase, script, "");
    }

    /**
     * Creates a stored transaction output.
     *
     * @param hash     The hash of the containing transaction.
     * @param index    The outpoint.
     * @param value    The value available.
     * @param height   The height this output was created in.
     * @param coinbase The coinbase flag.
     * @param address  The address.
     */
    public UTXO(Sha256Hash hash,
                long index,
                Coin value,
                int height,
                boolean coinbase,
                Script script,
                String address) {
        this.hash = checkNotNull(hash);
        this.index = index;
        this.value = checkNotNull(value);
        this.height = height;
        this.script = script;
        this.coinbase = coinbase;
        this.address = address;
    }

    /** The value which this Transaction output holds. */
    public Coin getValue() {
        return value;
    }

    /** The Script object which you can use to get address, script bytes or script type. */
    public Script getScript() {
        return script;
    }

    /** The hash of the transaction which holds this output. */
    public Sha256Hash getHash() {
        return hash;
    }

    /** The index of this output in the transaction which holds it. */
    public long getIndex() {
        return index;
    }

    /** Gets the height of the block that created this output. */
    public int getHeight() {
        return height;
    }

    /** Gets the flag of whether this was created by a coinbase tx. */
    public boolean isCoinbase() {
        return coinbase;
    }

    /** The address of this output, can be the empty string if none was provided at construction time or was deserialized */
    public String getAddress() {
        return address;
    }

    @Override
    public String toString() {
        return String.format(Locale.US, "Stored TxOut of %s (%s:%d)", value.toFriendlyString(), hash, index);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getIndex(), getHash(), getValue());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UTXO other = (UTXO) o;
        return getIndex() == other.getIndex() && getHash().equals(other.getHash()) && getValue().equals(((UTXO) o).getValue());
    }

    public void serializeToStream(OutputStream bos) throws IOException {
        Utils.uint64ToByteStreamLE(BigInteger.valueOf(value.value), bos);
        byte[] scriptBytes = script.getProgram();
        Utils.uint32ToByteStreamLE(scriptBytes.length, bos);
        bos.write(scriptBytes);
        bos.write(hash.getBytes());
        Utils.uint32ToByteStreamLE(index, bos);
        Utils.uint32ToByteStreamLE(height, bos);
        bos.write(new byte[] { (byte)(coinbase ? 1 : 0) });
    }

    public static UTXO fromStream(InputStream in) throws IOException {
        byte[] valueBytes = new byte[8];
        if (in.read(valueBytes, 0, 8) != 8)
            throw new EOFException();
        Coin value = Coin.valueOf(Utils.readInt64(valueBytes, 0));

        int scriptBytesLength = (int) Utils.readUint32FromStream(in);
        byte[] scriptBytes = new byte[scriptBytesLength];
        if (in.read(scriptBytes) != scriptBytesLength)
            throw new EOFException();
        Script script = new Script(scriptBytes);

        byte[] hashBytes = new byte[32];
        if (in.read(hashBytes) != 32)
            throw new EOFException();
        Sha256Hash hash = Sha256Hash.wrap(hashBytes);

        byte[] indexBytes = new byte[4];
        if (in.read(indexBytes) != 4)
            throw new EOFException();
        long index = Utils.readUint32(indexBytes, 0);

        int height = (int) Utils.readUint32FromStream(in);

        byte[] coinbaseByte = new byte[1];
        in.read(coinbaseByte);
        boolean coinbase = coinbaseByte[0] == 1;

        return new UTXO(hash, index, value, height, coinbase, script);
    }
}
