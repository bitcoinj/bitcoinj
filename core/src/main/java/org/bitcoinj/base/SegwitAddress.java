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
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.core.NetworkParameters;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.bitcoinj.base.BitcoinNetwork.*;

/**
 * <p>Implementation of native segwit addresses. They are composed of two parts:</p>
 *
 * <ul>
 * <li>A human-readable part (HRP) which is a string the specifies the network. See
 * {@link SegwitAddress.SegwitHrp}.</li>
 * <li>A data part, containing the witness version (encoded as an OP_N operator) and program (encoded by re-arranging
 * bits into groups of 5).</li>
 * </ul>
 *
 * <p>See <a href="https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki">BIP350</a> and
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki">BIP173</a> for details.</p>
 *
 * <p>However, you don't need to care about the internals. Use {@link #fromBech32(Network, String)},
 * {@link #fromHash(org.bitcoinj.base.Network, byte[])} or {@link ECKey#toAddress(ScriptType, Network)}
 * to construct a native segwit address.</p>
 */
public class SegwitAddress implements Address {
    public static final int WITNESS_PROGRAM_LENGTH_PKH = 20;
    public static final int WITNESS_PROGRAM_LENGTH_SH = 32;
    public static final int WITNESS_PROGRAM_LENGTH_TR = 32;
    public static final int WITNESS_PROGRAM_MIN_LENGTH = 2;
    public static final int WITNESS_PROGRAM_MAX_LENGTH = 40;


    /**
     * Human-readable part (HRP) of Segwit addresses for standard Bitcoin networks.
     * <p>
     * See <a href="https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Segwit_address_format">BIP 173 definition of {@code bc} and {@code tb} HRPs</a> and
     *  <a href="https://github.com/bitcoin/bitcoin/issues/12314">Bitcoin Core Issue 1234 - discussion of {@code bcrt} HRP</a> for details.
     */
    public enum SegwitHrp {
        BC(MAINNET),
        TB(TESTNET, SIGNET),
        BCRT(REGTEST);

        private final EnumSet<BitcoinNetwork> networks;

        SegwitHrp(BitcoinNetwork n) {
            networks = EnumSet.of(n);
        }

        SegwitHrp(BitcoinNetwork n1, BitcoinNetwork n2) {
            networks = EnumSet.of(n1, n2);
        }

        /**
         * Get the HRP in lowercase. To get uppercase, use {@link SegwitHrp#name()}
         * @return HRP in lowercase.
         */
        public String toString() {
            return name().toLowerCase();
        }

        /**
         * @param hrp uppercase or lowercase HRP
         * @return the corresponding enum
         * @throws IllegalArgumentException if unknown string
         */
        public static SegwitHrp of(String hrp) {
            return SegwitHrp.valueOf(hrp.toUpperCase());
        }

        /**
         * @param hrp uppercase or lowercase HRP
         * @return Optional containing the corresponding enum or empty if not found
         */
        public static Optional<SegwitHrp> find(String hrp) {
            try {
                return Optional.of(SegwitHrp.of(hrp));
            } catch(IllegalArgumentException iae) {
                return Optional.empty();
            }
        }

        /**
         * @param network network enum
         * @return the corresponding enum
         */
        public static SegwitHrp ofNetwork(BitcoinNetwork network) {
            return Stream.of(SegwitHrp.values())
                    .filter(hrp -> hrp.networks.contains(network))
                    .findFirst()
                    .orElseThrow(IllegalStateException::new);
        }
    }

    protected final Network network;
    protected final short witnessVersion;
    protected final byte[] witnessProgram;          // In 8-bits per byte format

    private static Network normalizeNetwork(Network network) {
        // SegwitAddress does not distinguish between the SIGNET and TESTNET, normalize to TESTNET
        if (network instanceof BitcoinNetwork) {
            BitcoinNetwork bitcoinNetwork = (BitcoinNetwork) network;
            if (bitcoinNetwork == BitcoinNetwork.SIGNET) {
                return BitcoinNetwork.TESTNET;
            }
        }
        return network;
    }

    private static byte[] encode8to5(byte[] data) {
        return convertBits(data, 0, data.length, 8, 5, true);
    }

    private static byte[] decode5to8(byte[] data) {
        return convertBits(data, 0, data.length, 5, 8, false);
    }

    /**
     * Private constructor. Use {@link #fromBech32(Network, String)},
     * {@link #fromHash(Network, byte[])} or {@link ECKey#toAddress(ScriptType, Network)}.
     * 
     * @param network
     *            network this address is valid for
     * @param witnessVersion
     *            version number between 0 and 16
     * @param witnessProgram
     *            hash of pubkey, pubkey or script (depending on version) (8-bits per byte)
     * @throws AddressFormatException
     *             if any of the sanity checks fail
     */
    private SegwitAddress(Network network, int witnessVersion, byte[] witnessProgram) throws AddressFormatException {
        if (witnessVersion < 0 || witnessVersion > 16)
            throw new AddressFormatException("Invalid script version: " + witnessVersion);
        if (witnessProgram.length < WITNESS_PROGRAM_MIN_LENGTH || witnessProgram.length > WITNESS_PROGRAM_MAX_LENGTH)
            throw new AddressFormatException.InvalidDataLength("Invalid length: " + witnessProgram.length);
        // Check script length for version 0:
        // BIP 141:
        // "If the version byte is 0, but the witness program is neither 20 nor 32 bytes, the script must fail."
        // In other words: coins sent to addresses with other lengths will become unspendable.
        if (witnessVersion == 0 && witnessProgram.length != WITNESS_PROGRAM_LENGTH_PKH
                && witnessProgram.length != WITNESS_PROGRAM_LENGTH_SH)
            throw new AddressFormatException.InvalidDataLength(
                    "Invalid length for address version 0: " + witnessProgram.length);
        // Check script length for version 1:
        // BIP 341:
        // "A Taproot output is a native SegWit output (see BIP141) with version number 1, and a 32-byte
        // witness program. Any other outputs, including version 1 outputs with lengths other than 32 bytes,
        // or P2SH-wrapped version 1 outputs, remain unencumbered."
        // In other words: other lengths are not valid Taproot scripts but coins sent there won't be
        // unspendable, quite the contrary, they will be anyone-can-spend. (Not that easy spendable, because still
        // not-standard outputs and therefore not relayed, but a willing miner could easily spend them.)

        // Rationale for still restricting length here: creating anyone-can-spend Taproot addresses is probably
        // not that what callers expect.
        if (witnessVersion == 1 && witnessProgram.length != WITNESS_PROGRAM_LENGTH_TR)
            throw new AddressFormatException.InvalidDataLength(
                    "Invalid length for address version 1: " + witnessProgram.length);
        this.network = normalizeNetwork(checkNotNull(network));
        this.witnessVersion = (short) witnessVersion;
        this.witnessProgram = checkNotNull(witnessProgram);
    }

    /**
     * Returns the witness version in decoded form. Only versions 0 and 1 are in use right now.
     * 
     * @return witness version, between 0 and 16
     */
    public int getWitnessVersion() {
        return witnessVersion;
    }

    /**
     * Returns the witness program in decoded form.
     * 
     * @return witness program
     */
    public byte[] getWitnessProgram() {
        // no version byte
        return witnessProgram;
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
        if (version == 0) {
            int programLength = getWitnessProgram().length;
            if (programLength == WITNESS_PROGRAM_LENGTH_PKH)
                return ScriptType.P2WPKH;
            if (programLength == WITNESS_PROGRAM_LENGTH_SH)
                return ScriptType.P2WSH;
            throw new IllegalStateException(); // cannot happen
        } else if (version == 1) {
            int programLength = getWitnessProgram().length;
            if (programLength == WITNESS_PROGRAM_LENGTH_TR)
                return ScriptType.P2TR;
            throw new IllegalStateException(); // cannot happen
        }
        throw new IllegalStateException("cannot handle: " + version);
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
     * @deprecated Use {@link AddressParser#parseAddress(String, Network)} or {@link AddressParser#parseAddressAnyNetwork(String)}
     */
    @Deprecated
    public static SegwitAddress fromBech32(@Nullable NetworkParameters params, String bech32)
            throws AddressFormatException {
        AddressParser parser = DefaultAddressParser.fromNetworks();
        return (SegwitAddress) (params != null
                ? parser.parseAddress(bech32, params.network())
                : parser.parseAddressAnyNetwork(bech32)
        );
    }

    /**
     * Construct a {@link SegwitAddress} from its textual form.
     *
     * @param network expected network this address is valid for
     * @param bech32 bech32-encoded textual form of the address
     * @return constructed address
     * @throws AddressFormatException if something about the given bech32 address isn't right
     */
    public static SegwitAddress fromBech32(@Nonnull Network network, String bech32)
            throws AddressFormatException {
        Bech32.Bech32Data bechData = Bech32.decode(bech32);
        if (bechData.hrp.equals(network.segwitAddressHrp()))
            return fromBechData(network, bechData);
        throw new AddressFormatException.WrongNetwork(bechData.hrp);
    }

    private static SegwitAddress fromBechData(Network network, Bech32.Bech32Data bechData) {
        if (bechData.data.length < 1) {
            throw new AddressFormatException.InvalidDataLength("invalid address length (0)");
        }
        final int witnessVersion = bechData.data[0];
        byte[] witnessProgram = decode5to8(trimVersion(bechData.data));
        final SegwitAddress address = new SegwitAddress(network, witnessVersion, witnessProgram);
        if ((witnessVersion == 0 && bechData.encoding != Bech32.Encoding.BECH32) ||
                (witnessVersion != 0 && bechData.encoding != Bech32.Encoding.BECH32M))
            throw new AddressFormatException.UnexpectedWitnessVersion("Unexpected witness version: " + witnessVersion);
        return address;
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
     * @deprecated Use {@link #fromHash(Network, byte[])}
     */
    @Deprecated
    public static SegwitAddress fromHash(NetworkParameters params, byte[] hash) {
        return fromHash(params.network(), hash);
    }

    /**
     * Construct a {@link SegwitAddress} that represents the given hash, which is either a pubkey hash or a script hash.
     * The resulting address will be either a P2WPKH or a P2WSH type of address.
     *
     * @param network network this address is valid for
     * @param hash 20-byte pubkey hash or 32-byte script hash
     * @return constructed address
     */
    public static SegwitAddress fromHash(Network network, byte[] hash) {
        return new SegwitAddress(network, 0, hash);
    }

    /**
     * Construct a {@link SegwitAddress} that represents the given program, which is either a pubkey, a pubkey hash
     * or a script hash – depending on the script version. The resulting address will be either a P2WPKH, a P2WSH or
     * a P2TR type of address.
     *
     * @param params
     *            network this address is valid for
     * @param witnessVersion
     *            version number between 0 and 16
     * @param witnessProgram
     *            version dependent witness program
     * @return constructed address
     * @deprecated Use {@link #fromProgram(Network, int, byte[])}
     */
    @Deprecated
    public static SegwitAddress fromProgram(NetworkParameters params, int witnessVersion, byte[] witnessProgram) {
        return fromProgram(params.network(), witnessVersion, witnessProgram);
    }

    /**
     * Construct a {@link SegwitAddress} that represents the given program, which is either a pubkey, a pubkey hash
     * or a script hash – depending on the script version. The resulting address will be either a P2WPKH, a P2WSH or
     * a P2TR type of address.
     *
     * @param network network this address is valid for
     * @param witnessVersion version number between 0 and 16
     * @param witnessProgram version dependent witness program
     * @return constructed address
     */
    public static SegwitAddress fromProgram(Network network, int witnessVersion, byte[] witnessProgram) {
        return new SegwitAddress(network, witnessVersion, witnessProgram);
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
     * @deprecated Use {@link ECKey#toAddress(ScriptType, org.bitcoinj.base.Network)}
     */
    @Deprecated
    public static SegwitAddress fromKey(NetworkParameters params, ECKey key) {
        return (SegwitAddress) key.toAddress(ScriptType.P2WPKH, params.network());
    }

    /**
     * Get the network this address works on. Use of {@link BitcoinNetwork} is preferred to use of {@link NetworkParameters}
     * when you need to know what network an address is for.
     * @return the Network.
     */
    @Override
    public Network network() {
        return network;
    }

    @Override
    public int hashCode() {
        return Objects.hash(network, witnessVersion, Arrays.hashCode(witnessProgram));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SegwitAddress other = (SegwitAddress) o;
        return this.network == other.network && witnessVersion == other.witnessVersion && Arrays.equals(this.witnessProgram, other.witnessProgram);
    }

    /**
     * Returns the textual form of the address.
     * 
     * @return textual form encoded in bech32
     */
    public String toBech32() {
        Bech32.Encoding encoding = (witnessVersion == 0) ?  Bech32.Encoding.BECH32 : Bech32.Encoding.BECH32M;
        return Bech32.encode(encoding, network.segwitAddressHrp(), appendVersion(witnessVersion, encode8to5(witnessProgram)));
    }

    // Trim the version byte and return the witness program only
    private static byte[] trimVersion(byte[] data) {
        byte[] program = new byte[data.length - 1];
        System.arraycopy(data, 1, program, 0, program.length);
        return program;
    }

    // concatenate the witnessVersion and witnessProgram
    private static byte[] appendVersion(short version, byte[] program) {
        byte[] data = new byte[program.length + 1];
        data[0] = (byte) version;
        System.arraycopy(program, 0, data, 1, program.length);
        return data;
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

    // Comparator for SegwitAddress, left argument must be SegwitAddress, right argument can be any Address
    private static final Comparator<Address> SEGWIT_ADDRESS_COMPARATOR = Address.PARTIAL_ADDRESS_COMPARATOR
            .thenComparing(a -> ((SegwitAddress) a).witnessVersion)
            .thenComparing(a -> ((SegwitAddress) a).witnessProgram, ByteUtils.arrayUnsignedComparator());  // Then compare Segwit bytes

    /**
     * {@inheritDoc}
     *
     * @param o other {@code Address} object
     * @return comparison result
     */
    @Override
    public int compareTo(Address o) {
        return SEGWIT_ADDRESS_COMPARATOR.compare(this, o);
    }
}
