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

package org.bitcoinj.base;

import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.base.internal.ByteArray;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Locale;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * Implementation of the Bech32 encoding. Used in the implementation of {@link SegwitAddress} and
 * also provides an API for encoding/decoding arbitrary Bech32 data. To parse Bech32 Bitcoin addresses,
 * use {@link AddressParser}. To encode arbitrary Bech32 data, see {@link #encodeBytes(Encoding, String, byte[])}.
 * To decode arbitrary Bech32 strings, see {@link #decodeBytes(String, String, Encoding)} or {@link #decode(String)}.
 * <p>
 * Based on the original Coinomi implementation.
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki">BIP173</a>
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki">BIP350</a>
 */
public class Bech32 {
    /** The Bech32 character set for encoding. */
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /** The Bech32 character set for decoding. */
    private static final byte[] CHARSET_REV = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
             1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
             1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    };

    private static final int BECH32_CONST = 1;
    private static final int BECH32M_CONST = 0x2bc830a3;

    /**
     * Enumeration of known Bech32 encoding format types: Bech32 and Bech32m.
     */
    public enum Encoding { BECH32, BECH32M }

    /**
     * Binary data in 5-bits-per-byte format as used in Bech32 encoding/decoding.
     */
    public static class Bech32Bytes extends ByteArray {
        /**
         * Wrapper for a {@code byte[]} array.
         *
         * @param bytes bytes to be copied (5-bits per byte format)
         */
        protected Bech32Bytes(byte[] bytes) {
            super(bytes);
        }

        /**
         * Construct an instance, from two parts. Useful for the Segwit implementation,
         * see {@link #ofSegwit(short, byte[])}.
         * @param first first byte (5-bits per byte format)
         * @param rest remaining bytes (5-bits per byte format)
         */
        private Bech32Bytes(byte first, byte[] rest) {
            super(concat(first, rest));
        }

        private static byte[] concat(byte first, byte[] rest) {
            byte[] bytes = new byte[rest.length + 1];
            bytes[0] =  first;
            System.arraycopy(rest, 0, bytes, 1, rest.length);
            return bytes;
        }

        /**
         * Create an instance from arbitrary data, converts from 8-bits per byte
         * format to 5-bits per byte format before construction.
         * @param data arbitrary byte array (8-bits of data per byte)
         * @return Bech32 instance containing 5-bit encoding
         */
        static Bech32Bytes ofBytes(byte[] data) {
            return new Bech32Bytes(encode8to5(data));
        }

        /**
         * Create an instance from Segwit address binary data.
         * @param witnessVersion A short containing (5-bit) witness version information
         * @param witnessProgram a witness program (8-bits-per byte)
         * @return Bech32 instance containing 5-bit encoding
         */
        static Bech32Bytes ofSegwit(short witnessVersion, byte[] witnessProgram) {
            // convert witnessVersion, witnessProgram to 5-bit Bech32Bytes
            return new Bech32Bytes((byte) (witnessVersion & 0xff), encode8to5(witnessProgram));
        }

        private static byte[] encode8to5(byte[] data) {
            return convertBits(data, 0, data.length, 8, 5, true);
        }

        /**
         * Return the data, fully-decoded with 8-bits per byte.
         * @return The data, fully-decoded as a byte array.
         */
        public byte[] decode5to8() {
            return convertBits(bytes, 0, bytes.length, 5, 8, false);
        }

        /**
         * @return the first byte (witness version if instance is a Segwit address)
         */
        short witnessVersion() {
            return bytes[0];
        }

        // Trim the version byte and return the witness program only
        private Bech32Bytes stripFirst() {
            byte[] program = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, program, 0, program.length);
            return new Bech32Bytes(program);
        }

        /**
         * Assuming this instance contains a Segwit address, return the witness program portion of the data.
         * @return The witness program as a byte array
         */
        byte[] witnessProgram() {
            return stripFirst().decode5to8();
        }
    }

    /**
     * Bech32 data in 5-bit byte format with {@link Encoding} and human-readable part (HRP) information.
     * Typically, the result of {@link #decode(String)}.
     */
    public static class Bech32Data extends Bech32Bytes {
        public final Encoding encoding;
        public final String hrp;

        private Bech32Data(final Encoding encoding, final String hrp, final byte[] data) {
            super(data);
            this.encoding = encoding;
            this.hrp = hrp;
        }
    }

    /** Find the polynomial with value coefficients mod the generator as 30-bit. */
    private static int polymod(final byte[] values) {
        int c = 1;
        for (byte v_i: values) {
            int c0 = (c >>> 25) & 0xff;
            c = ((c & 0x1ffffff) << 5) ^ (v_i & 0xff);
            if ((c0 &  1) != 0) c ^= 0x3b6a57b2;
            if ((c0 &  2) != 0) c ^= 0x26508e6d;
            if ((c0 &  4) != 0) c ^= 0x1ea119fa;
            if ((c0 &  8) != 0) c ^= 0x3d4233dd;
            if ((c0 & 16) != 0) c ^= 0x2a1462b3;
        }
        return c;
    }

    /** Expand a HRP for use in checksum computation. */
    private static byte[] expandHrp(final String hrp) {
        int hrpLength = hrp.length();
        byte ret[] = new byte[hrpLength * 2 + 1];
        for (int i = 0; i < hrpLength; ++i) {
            int c = hrp.charAt(i) & 0x7f; // Limit to standard 7-bit ASCII
            ret[i] = (byte) ((c >>> 5) & 0x07);
            ret[i + hrpLength + 1] = (byte) (c & 0x1f);
        }
        ret[hrpLength] = 0;
        return ret;
    }

    /** Verify a checksum. */
    @Nullable
    private static Encoding verifyChecksum(final String hrp, final byte[] values) {
        byte[] hrpExpanded = expandHrp(hrp);
        byte[] combined = new byte[hrpExpanded.length + values.length];
        System.arraycopy(hrpExpanded, 0, combined, 0, hrpExpanded.length);
        System.arraycopy(values, 0, combined, hrpExpanded.length, values.length);
        final int check = polymod(combined);
        if (check == BECH32_CONST)
            return Encoding.BECH32;
        else if (check == BECH32M_CONST)
            return Encoding.BECH32M;
        else
            return null;
    }

    /** Create a checksum. */
    private static byte[] createChecksum(final Encoding encoding, final String hrp, final byte[] values)  {
        byte[] hrpExpanded = expandHrp(hrp);
        byte[] enc = new byte[hrpExpanded.length + values.length + 6];
        System.arraycopy(hrpExpanded, 0, enc, 0, hrpExpanded.length);
        System.arraycopy(values, 0, enc, hrpExpanded.length, values.length);
        int mod = polymod(enc) ^ (encoding == Encoding.BECH32 ? BECH32_CONST : BECH32M_CONST);
        byte[] ret = new byte[6];
        for (int i = 0; i < 6; ++i) {
            ret[i] = (byte) ((mod >>> (5 * (5 - i))) & 31);
        }
        return ret;
    }

    /**
     * Encode a byte array to a Bech32 string
     * @param encoding Desired encoding Bech32 or Bech32m
     * @param hrp human-readable part to use for encoding
     * @param bytes Arbitrary binary data (8-bits per byte)
     * @return A Bech32 string
     */
    public static String encodeBytes(Encoding encoding, String hrp, byte[] bytes) {
        return encode(encoding, hrp, Bech32Bytes.ofBytes(bytes));
    }

    /**
     * Decode a Bech32 string to a byte array.
     * @param bech32 A Bech32 format string
     * @param expectedHrp Expected value for the human-readable part
     * @param expectedEncoding Expected encoding
     * @return Decoded value as byte array (8-bits per byte)
     * @throws AddressFormatException if unexpected hrp or encoding
     */
    public static byte[] decodeBytes(String bech32, String expectedHrp, Encoding expectedEncoding) {
        Bech32.Bech32Data decoded = decode(bech32);
        if (!decoded.hrp.equals(expectedHrp) || decoded.encoding != expectedEncoding) {
            throw new AddressFormatException("unexpected hrp or encoding");
        }
        return decoded.decode5to8();
    }

    /**
     * Encode a Bech32 string.
     * @param bech32 Contains 5-bits/byte data, desired encoding and human-readable part
     * @return A string containing the Bech32-encoded data
     */
    public static String encode(final Bech32Data bech32) {
        return encode(bech32.encoding, bech32.hrp, bech32);
    }

    /**
     * Encode a Bech32 string.
     * @param encoding The requested encoding
     * @param hrp The requested human-readable part
     * @param values Binary data in 5-bit per byte format
     * @return A string containing the Bech32-encoded data
     */
    public static String encode(Encoding encoding, String hrp, Bech32Bytes values) {
        checkArgument(hrp.length() >= 1, () -> "human-readable part is too short: " + hrp.length());
        checkArgument(hrp.length() <= 83, () -> "human-readable part is too long: " + hrp.length());
        String lcHrp = hrp.toLowerCase(Locale.ROOT);
        byte[] checksum = createChecksum(encoding, lcHrp, values.bytes());
        byte[] combined = new byte[values.bytes().length + checksum.length];
        System.arraycopy(values.bytes(), 0, combined, 0, values.bytes().length);
        System.arraycopy(checksum, 0, combined, values.bytes().length, checksum.length);
        StringBuilder sb = new StringBuilder(lcHrp.length() + 1 + combined.length);
        sb.append(lcHrp);
        sb.append('1');
        for (byte b : combined) {
            sb.append(CHARSET.charAt(b));
        }
        return sb.toString();
    }

    /**
     * Decode a Bech32 string.
     * <p>
     * To get the fully-decoded data, call {@link Bech32Bytes#decode5to8()} on the returned {@code Bech32Data}.
     * @param str A string containing Bech32-encoded data
     * @return An object with the detected encoding, hrp, and decoded data (in 5-bit per byte format)
     * @throws AddressFormatException if the string is invalid
     */
    public static Bech32Data decode(final String str) throws AddressFormatException {
        boolean lower = false, upper = false;
        if (str.length() < 8)
            throw new AddressFormatException.InvalidDataLength("Input too short: " + str.length());
        if (str.length() > 90)
            throw new AddressFormatException.InvalidDataLength("Input too long: " + str.length());
        for (int i = 0; i < str.length(); ++i) {
            char c = str.charAt(i);
            if (c < 33 || c > 126) throw new AddressFormatException.InvalidCharacter(c, i);
            if (c >= 'a' && c <= 'z') {
                if (upper)
                    throw new AddressFormatException.InvalidCharacter(c, i);
                lower = true;
            }
            if (c >= 'A' && c <= 'Z') {
                if (lower)
                    throw new AddressFormatException.InvalidCharacter(c, i);
                upper = true;
            }
        }
        final int pos = str.lastIndexOf('1');
        if (pos < 1) throw new AddressFormatException.InvalidPrefix("Missing human-readable part");
        final int dataPartLength = str.length() - 1 - pos;
        if (dataPartLength < 6) throw new AddressFormatException.InvalidDataLength("Data part too short: " + dataPartLength);
        byte[] values = new byte[dataPartLength];
        for (int i = 0; i < dataPartLength; ++i) {
            char c = str.charAt(i + pos + 1);
            if (CHARSET_REV[c] == -1) throw new AddressFormatException.InvalidCharacter(c, i + pos + 1);
            values[i] = CHARSET_REV[c];
        }
        String hrp = str.substring(0, pos).toLowerCase(Locale.ROOT);
        Encoding encoding = verifyChecksum(hrp, values);
        if (encoding == null) throw new AddressFormatException.InvalidChecksum();
        return new Bech32Data(encoding, hrp, Arrays.copyOfRange(values, 0, values.length - 6));
    }

    /**
     * Helper for re-arranging bits into groups.
     */
    private static byte[] convertBits(final byte[] in, final int inStart, final int inLen, final int fromBits,
                              final int toBits, final boolean pad) throws AddressFormatException {
        int acc = 0;
        int bits = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        final int maxv = (1 << toBits) - 1;
        final int max_acc = (1 << (fromBits + toBits - 1)) - 1;
        for (int i = 0; i < inLen; i++) {
            int value = in[i + inStart] & 0xff;
            if ((value >>> fromBits) != 0) {
                throw new AddressFormatException(
                        String.format("Input value '%X' exceeds '%d' bit size", value, fromBits));
            }
            acc = ((acc << fromBits) | value) & max_acc;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                out.write((acc >>> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0)
                out.write((acc << (toBits - bits)) & maxv);
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            throw new AddressFormatException("Could not convert bits, invalid padding");
        }
        return out.toByteArray();
    }
}
