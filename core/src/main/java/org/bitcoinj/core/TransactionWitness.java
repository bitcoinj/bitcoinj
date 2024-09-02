/*
 * Copyright by the original author or authors.
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

import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.Buffers;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.InternalUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;

import javax.annotation.Nullable;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static org.bitcoinj.base.internal.Preconditions.check;
import static org.bitcoinj.base.internal.Preconditions.checkArgument;

public class TransactionWitness {
    public static final TransactionWitness EMPTY = TransactionWitness.of(Collections.emptyList());

    /**
     * Creates the stack pushes necessary to redeem a P2WPKH output. If given signature is null, an empty push will be
     * used as a placeholder.
     */
    public static TransactionWitness redeemP2WPKH(@Nullable TransactionSignature signature, ECKey pubKey) {
        checkArgument(pubKey.isCompressed(), () ->
                "only compressed keys allowed");
        List<byte[]> pushes = new ArrayList<>(2);
        pushes.add(signature != null ? signature.encodeToBitcoin() : new byte[0]); // signature
        pushes.add(pubKey.getPubKey()); // pubkey
        return TransactionWitness.of(pushes);
    }

    /**
     * Creates the stack pushes necessary to redeem a P2WSH output.
     */
    public static TransactionWitness redeemP2WSH(Script witnessScript, TransactionSignature... signatures) {
        List<byte[]> pushes = new ArrayList<>(signatures.length + 2);
        pushes.add(new byte[] {});
        for (TransactionSignature signature : signatures)
            pushes.add(signature.encodeToBitcoin());
        pushes.add(witnessScript.program());
        return TransactionWitness.of(pushes);
    }

    /**
     * Construct a transaction witness from a given list of arbitrary pushes.
     *
     * @param pushes list of pushes
     * @return constructed transaction witness
     */
    public static TransactionWitness of(List<byte[]> pushes) {
        return new TransactionWitness(pushes);
    }

    /**
     * Construct a transaction witness from a given list of arbitrary pushes.
     *
     * @param pushes list of pushes
     * @return constructed transaction witness
     */
    public static TransactionWitness of(byte[]... pushes) {
        return of(Arrays.asList(pushes));
    }

    /**
     * Deserialize this transaction witness from a given payload.
     *
     * @param payload           payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static TransactionWitness read(ByteBuffer payload) throws BufferUnderflowException {
        VarInt pushCountVarInt = VarInt.read(payload);
        check(pushCountVarInt.fitsInt(), BufferUnderflowException::new);
        int pushCount = pushCountVarInt.intValue();
        List<byte[]> pushes = new ArrayList<>(Math.min(pushCount, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (int y = 0; y < pushCount; y++)
            pushes.add(Buffers.readLengthPrefixedBytes(payload));
        return new TransactionWitness(pushes);
    }

    private final List<byte[]> pushes;

    private TransactionWitness(List<byte[]> pushes) {
        for (byte[] push : pushes)
            Objects.requireNonNull(push);
        this.pushes = pushes;
    }

    public byte[] getPush(int i) {
        return pushes.get(i);
    }

    public int getPushCount() {
        return pushes.size();
    }

    /**
     * Write this transaction witness into the given buffer.
     *
     * @param buf buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the serialized data doesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        VarInt.of(pushes.size()).write(buf);
        for (byte[] push : pushes)
            Buffers.writeLengthPrefixedBytes(buf, push);
        return buf;
    }

    /**
     * Allocates a byte array and writes this transaction witness into it.
     *
     * @return byte array containing the transaction witness
     */
    public byte[] serialize() {
        return write(ByteBuffer.allocate(messageSize())).array();
    }

    /**
     * Return the size of the serialized message. Note that if the message was deserialized from a payload, this
     * size can differ from the size of the original payload.
     *
     * @return size of the serialized message in bytes
     */
    public int messageSize() {
        int size = VarInt.sizeOf(pushes.size());
        for (byte[] push : pushes)
            size += VarInt.sizeOf(push.length) + push.length;
        return size;
    }

    @Override
    public String toString() {
        List<String> stringPushes = new ArrayList<>(pushes.size());
        for (byte[] push : pushes) {
            if (push.length == 0) {
                stringPushes.add("EMPTY");
            } else {
                stringPushes.add(ByteUtils.formatHex(push));
            }
        }
        return InternalUtils.SPACE_JOINER.join(stringPushes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionWitness other = (TransactionWitness) o;
        if (pushes.size() != other.pushes.size()) return false;
        for (int i = 0; i < pushes.size(); i++) {
            if (!Arrays.equals(pushes.get(i), other.pushes.get(i))) return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hashCode = 1;
        for (byte[] push : pushes) {
            hashCode = 31 * hashCode + Arrays.hashCode(push);
        }
        return hashCode;
    }
}
