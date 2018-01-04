/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.script;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.script.ScriptOpCodes.OP_0;
import static org.bitcoinj.script.ScriptOpCodes.OP_1;
import static org.bitcoinj.script.ScriptOpCodes.OP_16;
import static org.bitcoinj.script.ScriptOpCodes.OP_1NEGATE;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA1;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA2;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA4;
import static org.bitcoinj.script.ScriptOpCodes.getOpCodeName;
import static org.bitcoinj.script.ScriptOpCodes.getPushDataName;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import javax.annotation.Nullable;

import org.bitcoinj.core.Utils;

import com.google.common.base.Objects;
import com.google.common.base.Optional;

/**
 * A script element that is either a data push (signature, pubkey, etc) or a non-push (logic, numeric, etc) operation.
 */
public final class ScriptChunk {
    private final int opcode;
    @Nullable
    private final byte[] data;
    private int startLocationInProgram;

    private static final byte[] OP_0_BYTE_ARRAY = new byte[]{};

    public ScriptChunk(int opcode, byte[] data) {
        this(opcode, data, -1);
        if (isPushData() && (opcode == OP_0 || opcode == OP_1NEGATE || (opcode >= OP_1 && opcode <= OP_16)))
            checkArgument(data == null, "Data must be null for opcode "+opcode);
    }

    public ScriptChunk(int opcode, byte[] data, int startLocationInProgram) {
        this.opcode = opcode;
        this.data = data == null? null : Arrays.copyOf(data, data.length);
        this.startLocationInProgram = startLocationInProgram;
    }

    /**
     * Operation to be executed. Opcodes are defined in {@link ScriptOpCodes}.
     * @return the opcode for this operation.
     */
    public int getOpcode() {
        return opcode;
    }

    /**
     * For push operations, this is the vector to be pushed on the stack. For {@link ScriptOpCodes#OP_0}, the vector is
     * empty. Return an empty optional for non-push operations.
     * <p>The data is represented in little-endian.</p>
     * @return an {@link Optional} with the data for push operations, empty otherwise.
     * @see ScriptChunk#isPushData()
     */
    public Optional<byte[]> getData() {
        if (opcode == OP_0)
            return Optional.of(OP_0_BYTE_ARRAY);
        if (opcode == OP_1NEGATE)
            return Optional.of(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE.negate(), false)));
        if (opcode >= OP_1 && opcode <= OP_16)
            return Optional.of(new byte[]{(byte)(opcode + 1 - OP_1)});
        return data == null? Optional.<byte[]>absent(): Optional.of(Arrays.copyOf(data, data.length));
    }

    /**
     * Decode the data vector for push operations.
     * @return the {@link Optional} value obtained decoding getData().
     * @see Utils#decodeMPI(byte[], boolean)
     * @see Utils#reverseBytes(byte[])
     */
    public Optional<BigInteger> getDataValue() {
        if (opcode == OP_0)
            return Optional.of(BigInteger.ZERO);
        if (opcode == OP_1NEGATE)
            return Optional.of(BigInteger.ONE.negate());
        if (opcode >= OP_1 && opcode <= OP_16)
            return Optional.of(BigInteger.valueOf(opcode + 1 - OP_1));
        return data == null? Optional.<BigInteger>absent(): Optional.of(Utils.decodeMPI(Utils.reverseBytes(data), false));
    }

    public boolean equalsOpCode(int opcode) {
        return opcode == this.opcode;
    }

    /**
     * If this chunk is a single byte of non-pushdata content (could be OP_RESERVED or some invalid Opcode)
     */
    public boolean isOpCode() {
        return opcode > OP_PUSHDATA4;
    }

    /**
     * Returns true if this chunk is pushdata content, including the single-byte pushdatas.
     */
    public boolean isPushData() {
        return opcode <= OP_16;
    }

    public int getStartLocationInProgram() {
        checkState(startLocationInProgram >= 0);
        return startLocationInProgram;
    }

    /** If this chunk is an OP_N opcode returns the equivalent integer value. */
    public int decodeOpN() {
        checkState(isOpCode());
        return Script.decodeFromOpN(opcode);
    }

    /**
     * Called on a pushdata chunk, returns true if it uses the smallest possible way (according to BIP62) to push the data.
     */
    public boolean isShortestPossiblePushData() {
        checkState(isPushData());
        if (data == null)
            return true;   // OP_N
        if (data.length == 0)
            return opcode == OP_0;
        if (data.length == 1) {
            byte b = data[0];
            if (b >= 0x01 && b <= 0x10)
                return opcode == OP_1 + b - 1;
            if ((b & 0xFF) == 0x81)
                return opcode == OP_1NEGATE;
        }
        if (data.length < OP_PUSHDATA1)
            return opcode == data.length;
        if (data.length < 256)
            return opcode == OP_PUSHDATA1;
        if (data.length < 65536)
            return opcode == OP_PUSHDATA2;

        // can never be used, but implemented for completeness
        return opcode == OP_PUSHDATA4;
    }

    public void write(OutputStream stream) throws IOException {
        if (isOpCode()) {
            checkState(data == null);
            stream.write(opcode);
        } else if (data != null) {
            if (opcode < OP_PUSHDATA1) {
                checkState(data.length == opcode);
                stream.write(opcode);
            } else if (opcode == OP_PUSHDATA1) {
                checkState(data.length <= 0xFF);
                stream.write(OP_PUSHDATA1);
                stream.write(data.length);
            } else if (opcode == OP_PUSHDATA2) {
                checkState(data.length <= 0xFFFF);
                stream.write(OP_PUSHDATA2);
                Utils.uint16ToByteStreamLE(data.length, stream);
            } else if (opcode == OP_PUSHDATA4) {
                checkState(data.length <= Script.MAX_SCRIPT_ELEMENT_SIZE);
                stream.write(OP_PUSHDATA4);
                Utils.uint32ToByteStreamLE(data.length, stream);
            } else {
                throw new RuntimeException("Unimplemented");
            }
            stream.write(data);
        } else {
            stream.write(opcode); // smallNum
        }
    }

    public byte[] toByteArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            write(stream);
        } catch (IOException e) {
            // Should not happen as ByteArrayOutputStream does not throw IOException on write
            throw new RuntimeException(e);
        }
        return stream.toByteArray();
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        if (isOpCode()) {
            buf.append(getOpCodeName(opcode));
        } else if (data != null) {
            // Data chunk
            buf.append(getPushDataName(opcode)).append("[").append(Utils.HEX.encode(data)).append("]");
        } else {
            // Small num
            buf.append(Script.decodeFromOpN(opcode));
        }
        return buf.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScriptChunk other = (ScriptChunk) o;
        return opcode == other.opcode && startLocationInProgram == other.startLocationInProgram
            && Arrays.equals(data, other.data);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(opcode, startLocationInProgram, Arrays.hashCode(data));
    }
}
