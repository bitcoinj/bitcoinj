/*
 * Copyright 2018 Andreas Schildbach
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

import java.io.ByteArrayOutputStream;

import javax.annotation.Nullable;

import org.bitcoinj.params.Networks;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;

import static com.google.common.base.Preconditions.checkState;

/**
 * <p>Implementation of native segwit addresses. They are composed of two parts:</p>
 *
 * <ul>
 * <li>A human-readable part (HRP) which is a string the specifies the network. See
 * {@link NetworkParameters#getSegwitAddressHrp()}.</li>
 * <li>A data part, containing the witness version (encoded as an OP_N operator) and program (encoded by re-arranging
 * bits into groups of 5).</li>
 * </ul>
 *
 * <p>See <a href="https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki">BIP173</a> for details.</p>
 *
 * <p>However, you don't need to care about the internals. Use {@link #fromBech32(NetworkParameters, String)},
 * {@link #fromHash(NetworkParameters, byte[])} or {@link #fromKey(NetworkParameters, ECKey)} to construct a native
 * segwit address.</p>
 */
public class SegwitAddress extends Address {
    public static final int WITNESS_PROGRAM_LENGTH_PKH = 20;
    public static final int WITNESS_PROGRAM_LENGTH_SH = 32;
    public static final int WITNESS_PROGRAM_MIN_LENGTH = 2;
    public static final int WITNESS_PROGRAM_MAX_LENGTH = 40;

    /**
     * Private constructor. Use {@link #fromBech32(NetworkParameters, String)},
     * {@link #fromHash(NetworkParameters, byte[])} or {@link #fromKey(NetworkParameters, ECKey)}.
     * 
     * @param params
     *            network this address is valid for
     * @param witnessVersion
     *            version number between 0 and 16
     * @param witnessProgram
     *            hash of pubkey or script (for version 0)
     */
    private SegwitAddress(NetworkParameters params, int witnessVersion, byte[] witnessProgram)
            throws AddressFormatException {
        this(params, encode(witnessVersion, witnessProgram));
    }

    /**
     * Helper for the above constructor.
     */
    private static byte[] encode(int witnessVersion, byte[] witnessProgram) throws AddressFormatException {
        byte[] convertedProgram = convertBits(witnessProgram, 0, witnessProgram.length, 8, 5, true);
        byte[] bytes = new byte[1 + convertedProgram.length];
        bytes[0] = (byte) (Script.encodeToOpN(witnessVersion) & 0xff);
        System.arraycopy(convertedProgram, 0, bytes, 1, convertedProgram.length);
        return bytes;
    }

    /**
     * Private constructor. Use {@link #fromBech32(NetworkParameters, String)},
     * {@link #fromHash(NetworkParameters, byte[])} or {@link #fromKey(NetworkParameters, ECKey)}.
     * 
     * @param params
     *            network this address is valid for
     * @param data
     *            in segwit address format, before bit re-arranging and bech32 encoding
     * @throws AddressFormatException
     *             if any of the sanity checks fail
     */
    private SegwitAddress(NetworkParameters params, byte[] data) throws AddressFormatException {
        super(params, data);
        if (data.length < 1)
            throw new AddressFormatException.InvalidDataLength("Zero data found");
        final int witnessVersion = getWitnessVersion();
        if (witnessVersion < 0 || witnessVersion > 16)
            throw new AddressFormatException("Invalid script version: " + witnessVersion);
        byte[] witnessProgram = getWitnessProgram();
        if (witnessProgram.length < WITNESS_PROGRAM_MIN_LENGTH || witnessProgram.length > WITNESS_PROGRAM_MAX_LENGTH)
            throw new AddressFormatException.InvalidDataLength("Invalid length: " + witnessProgram.length);
        // Check script length for version 0
        if (witnessVersion == 0 && witnessProgram.length != WITNESS_PROGRAM_LENGTH_PKH
                && witnessProgram.length != WITNESS_PROGRAM_LENGTH_SH)
            throw new AddressFormatException.InvalidDataLength(
                    "Invalid length for address version 0: " + witnessProgram.length);
    }

    /**
     * Returns the witness version in decoded form. Only version 0 is in use right now.
     * 
     * @return witness version, between 0 and 16
     */
    public int getWitnessVersion() {
        return bytes[0] & 0xff;
    }

    /**
     * Returns the witness program in decoded form.
     * 
     * @return witness program
     */
    public byte[] getWitnessProgram() {
        // skip version byte
        return convertBits(bytes, 1, bytes.length - 1, 5, 8, false);
    }

    @Override
    public byte[] getHash() {
        return getWitnessProgram();
    }

    /**
     * Get the type of output script that will be used for sending to the address. This is either
     * {@link ScriptType#P2WPKH} or {@link ScriptType#P2WSH}.
     * 
     * @return type of output script
     */
    @Override
    public ScriptType getOutputScriptType() {
        int version = getWitnessVersion();
        checkState(version == 0);
        int programLength = getWitnessProgram().length;
        if (programLength == WITNESS_PROGRAM_LENGTH_PKH)
            return ScriptType.P2WPKH;
        if (programLength == WITNESS_PROGRAM_LENGTH_SH)
            return ScriptType.P2WSH;
        throw new IllegalStateException("Cannot happen.");
    }

    @Override
    public String toString() {
        return toBech32();
    }

    /**
     * Construct a {@link SegwitAddress} from its textual form.
     * 
     * @param params
     *            expected network this address is valid for, or null if the network should be derived from the bech32
     * @param bech32
     *            bech32-encoded textual form of the address
     * @return constructed address
     * @throws AddressFormatException
     *             if something about the given bech32 address isn't right
     */
    public static SegwitAddress fromBech32(@Nullable NetworkParameters params, String bech32)
            throws AddressFormatException {
        Bech32.Bech32Data bechData = Bech32.decode(bech32);
        if (params == null) {
            for (NetworkParameters p : Networks.get()) {
                if (bechData.hrp.equals(p.getSegwitAddressHrp()))
                    return new SegwitAddress(p, bechData.data);
            }
            throw new AddressFormatException.InvalidPrefix("No network found for " + bech32);
        } else {
            if (bechData.hrp.equals(params.getSegwitAddressHrp()))
                return new SegwitAddress(params, bechData.data);
            throw new AddressFormatException.WrongNetwork(bechData.hrp);
        }
    }

    /**
     * Construct a {@link SegwitAddress} that represents the given hash, which is either a pubkey hash or a script hash.
     * The resulting address will be either a P2WPKH or a P2WSH type of address.
     * 
     * @param params
     *            network this address is valid for
     * @param hash
     *            20-byte pubkey hash or 32-byte script hash
     * @return constructed address
     */
    public static SegwitAddress fromHash(NetworkParameters params, byte[] hash) {
        return new SegwitAddress(params, 0, hash);
    }

    /**
     * Construct a {@link SegwitAddress} that represents the public part of the given {@link ECKey}. Note that an
     * address is derived from a hash of the public key and is not the public key itself.
     * 
     * @param params
     *            network this address is valid for
     * @param key
     *            only the public part is used
     * @return constructed address
     */
    public static SegwitAddress fromKey(NetworkParameters params, ECKey key) {
        return fromHash(params, key.getPubKeyHash());
    }

    /**
     * Returns the textual form of the address.
     * 
     * @return textual form encoded in bech32
     */
    public String toBech32() {
        return Bech32.encode(params.getSegwitAddressHrp(), bytes);
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
