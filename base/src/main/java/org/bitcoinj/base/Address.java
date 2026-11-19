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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.Comparator;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Secp256k1Constants.ALGORITHM_NAME;
import static org.bitcoinj.base.internal.Secp256k1Constants.COMPRESSED_FORMAT_NAME;
import static org.bitcoinj.base.internal.Secp256k1Constants.UNCOMPRESSED_FORMAT_NAME;

/**
 * Interface for addresses, e.g. native segwit addresses ({@link SegwitAddress}) or legacy addresses ({@link LegacyAddress}).
 * <p>
 * Use {@link AddressParser} to construct any kind of address from its textual form.
 */
public interface Address extends Comparable<Address> {
    /**
     * Get either the public key hash or script hash that is encoded in the address.
     * 
     * @return hash that is encoded in the address
     */
    byte[] getHash();

    /**
     * Get the type of output script that will be used for sending to the address.
     * 
     * @return type of output script
     */
    ScriptType getOutputScriptType();

    /**
     * Comparison field order for addresses is:
     * <ol>
     *     <li>{@link Network#id()}</li>
     *     <li>Legacy vs. Segwit</li>
     *     <li>(Legacy only) Version byte</li>
     *     <li>remaining {@code bytes}</li>
     * </ol>
     * <p>
     * Implementations use {@link Address#PARTIAL_ADDRESS_COMPARATOR} for tests 1 and 2.
     *
     * @param o other {@code Address} object
     * @return comparison result
     */
    @Override
    int compareTo(Address o);

    /**
     * Get the network this address is used on. Returns the <i>normalized</i> network (see below.)
     * <p>
     * <b>Note:</b> The network value returned is <i>normalized</i>. For example the address {@code "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"}
     * may be used on either {@link BitcoinNetwork#TESTNET} or {@link BitcoinNetwork#SIGNET}, but the value returned by
     * this method will always be {@link BitcoinNetwork#TESTNET}. Similarly, the address {@code "mnHUcqUVvrfi5kAaXJDQzBb9HsWs78b42R"}
     * may be used on {@link BitcoinNetwork#TESTNET}, {@link BitcoinNetwork#REGTEST}, or {@link BitcoinNetwork#REGTEST}, but
     * the value returned by this method will always be {@link BitcoinNetwork#TESTNET}.
     * @return the Network.
     */
    Network network();

    /**
     * Create a Bitcoin Address from a Secp256k1 {@link ECPublicKey} (Java Cryptography public key.)
     * <p>
     * Requires that a {@link java.security.Provider} providing {@code "RIPEMD160"} {@link MessageDigest} be installed.
     * For example, to install the Bouncy Castle Provider use:
     * <p>
     * {@code Security.addProvider(new BouncyCastleProvider());}
     * <p>
     * Since {@link org.bitcoinj.base} has minimal dependencies, it is the responsibility of the calling application
     * to make sure a {@code "RIPEMD160"} provider is on the class path and installed. See the {@code AddressFromKeyTest}
     * integration test for an example of how to do this.
     * @param publicKey a Secp256k1 public key
     * @param scriptType output script type
     * @param network network address will be used on
     * @return an address
     */
    static Address fromKey(ECPublicKey publicKey, ScriptType scriptType, BitcoinNetwork network) {
        checkArgument(publicKey.getAlgorithm().equals(ALGORITHM_NAME) &&
                (publicKey.getFormat().equals(COMPRESSED_FORMAT_NAME) || publicKey.getFormat().equals(UNCOMPRESSED_FORMAT_NAME)),
                () -> "publicKey algorithm must be 'Secp256k1' and format must be 'Compressed SEC' or 'Uncompressed SEC'" );
        byte [] pubKeyHash = sha256hash160(publicKey.getEncoded());
        if (scriptType == ScriptType.P2PKH) {
            return LegacyAddress.fromPubKeyHash(network, pubKeyHash);
        } else if (scriptType == ScriptType.P2WPKH) {
            return SegwitAddress.fromHash(network, pubKeyHash);
        } else {
            throw new UnsupportedOperationException("Script type not supported: " + scriptType);
        }
    }

    // Temporary until we can move (part of) CryptoUtils to `base`
    static byte[] sha256hash160(byte[] input) {
        byte[] sha256 = Sha256Hash.hash(input);
        return digestRipeMd160(sha256);
    }

    // Temporary until we can move (part of) CryptoUtils to `base`
    static byte[] digestRipeMd160(byte[] input) {
        byte[] pubKeyHash;
        try {
            pubKeyHash = MessageDigest.getInstance("RIPEMD160").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return pubKeyHash;
    }

    /**
     * Comparator for the first two comparison fields in {@code Address} comparisons, see {@link Address#compareTo(Address)}.
     * Used by {@link LegacyAddress#compareTo(Address)} and {@link SegwitAddress#compareTo(Address)}.
     * For use by implementing classes only.
     */
    Comparator<Address> PARTIAL_ADDRESS_COMPARATOR = Comparator
        .comparing((Address a) -> a.network().id()) // First compare network
        .thenComparing(Address::compareTypes);      // Then compare address type (subclass)

    /* private */
    static int compareTypes(Address a, Address b) {
        if (a instanceof LegacyAddress && b instanceof SegwitAddress) {
            return -1;  // Legacy addresses (starting with 1 or 3) come before Segwit addresses.
        } else if (a instanceof SegwitAddress && b instanceof LegacyAddress) {
            return 1;
        } else {
            return 0;   // Both are the same type: additional `thenComparing()` lambda(s) for that type must finish the comparison
        }
    }
}
