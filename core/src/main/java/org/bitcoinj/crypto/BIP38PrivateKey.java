/*
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

package org.bitcoinj.crypto;

import org.bitcoinj.core.*;
import org.bouncycastle.crypto.generators.SCrypt;

import com.google.common.primitives.Bytes;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkState;

/**
 * Implementation of <a href="https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki">BIP 38</a>
 * passphrase-protected private keys. Currently, only decryption is supported.
 */
public class BIP38PrivateKey extends PrefixedChecksummedBytes {
    public final boolean ecMultiply;
    public final boolean compressed;
    public final boolean hasLotAndSequence;
    public final byte[] addressHash;
    public final byte[] content;

    public static final class BadPassphraseException extends Exception {
    }

    /**
     * Construct a password-protected private key from its Base58 representation.
     * @param params
     *            The network parameters of the chain that the key is for.
     * @param base58
     *            The textual form of the password-protected private key.
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid
     */
    public static BIP38PrivateKey fromBase58(NetworkParameters params, String base58) throws AddressFormatException {
        byte[] versionAndDataBytes = Base58.decodeChecked(base58);
        int version = versionAndDataBytes[0] & 0xFF;
        byte[] bytes = Arrays.copyOfRange(versionAndDataBytes, 1, versionAndDataBytes.length);

        if (version != 0x01)
            throw new AddressFormatException.InvalidPrefix("Mismatched version number: " + version);
        if (bytes.length != 38)
            throw new AddressFormatException.InvalidDataLength("Wrong number of bytes: " + bytes.length);
        boolean hasLotAndSequence = (bytes[1] & 0x04) != 0; // bit 2
        boolean compressed = (bytes[1] & 0x20) != 0; // bit 5
        if ((bytes[1] & 0x01) != 0) // bit 0
            throw new AddressFormatException("Bit 0x01 reserved for future use.");
        if ((bytes[1] & 0x02) != 0) // bit 1
            throw new AddressFormatException("Bit 0x02 reserved for future use.");
        if ((bytes[1] & 0x08) != 0) // bit 3
            throw new AddressFormatException("Bit 0x08 reserved for future use.");
        if ((bytes[1] & 0x10) != 0) // bit 4
            throw new AddressFormatException("Bit 0x10 reserved for future use.");
        final int byte0 = bytes[0] & 0xff;
        final boolean ecMultiply;
        if (byte0 == 0x42) {
            // Non-EC-multiplied key
            if ((bytes[1] & 0xc0) != 0xc0) // bits 6+7
                throw new AddressFormatException("Bits 0x40 and 0x80 must be set for non-EC-multiplied keys.");
            ecMultiply = false;
            if (hasLotAndSequence)
                throw new AddressFormatException("Non-EC-multiplied keys cannot have lot/sequence.");
        } else if (byte0 == 0x43) {
            // EC-multiplied key
            if ((bytes[1] & 0xc0) != 0x00) // bits 6+7
                throw new AddressFormatException("Bits 0x40 and 0x80 must be cleared for EC-multiplied keys.");
            ecMultiply = true;
        } else {
            throw new AddressFormatException("Second byte must by 0x42 or 0x43.");
        }
        byte[] addressHash = Arrays.copyOfRange(bytes, 2, 6);
        byte[] content = Arrays.copyOfRange(bytes, 6, 38);
        return new BIP38PrivateKey(params, bytes, ecMultiply, compressed, hasLotAndSequence, addressHash, content);
    }

    private BIP38PrivateKey(NetworkParameters params, byte[] bytes, boolean ecMultiply, boolean compressed,
            boolean hasLotAndSequence, byte[] addressHash, byte[] content) throws AddressFormatException {
        super(params, bytes);
        this.ecMultiply = ecMultiply;
        this.compressed = compressed;
        this.hasLotAndSequence = hasLotAndSequence;
        this.addressHash = addressHash;
        this.content = content;
    }

    /**
     * Returns the base58-encoded textual form, including version and checksum bytes.
     * 
     * @return textual form
     */
    public String toBase58() {
        return Base58.encodeChecked(1, bytes);
    }

    public ECKey decrypt(String passphrase) throws BadPassphraseException {
        String normalizedPassphrase = Normalizer.normalize(passphrase, Normalizer.Form.NFC);
        ECKey key = ecMultiply ? decryptEC(normalizedPassphrase) : decryptNoEC(normalizedPassphrase);
        Sha256Hash hash = Sha256Hash.twiceOf(LegacyAddress.fromKey(params, key).toString().getBytes(StandardCharsets.US_ASCII));
        byte[] actualAddressHash = Arrays.copyOfRange(hash.getBytes(), 0, 4);
        if (!Arrays.equals(actualAddressHash, addressHash))
            throw new BadPassphraseException();
        return key;
    }

    private ECKey decryptNoEC(String normalizedPassphrase) {
        try {
            byte[] derived = SCrypt.generate(normalizedPassphrase.getBytes(StandardCharsets.UTF_8), addressHash, 16384, 8, 8, 64);
            byte[] key = Arrays.copyOfRange(derived, 32, 64);
            SecretKeySpec keyspec = new SecretKeySpec(key, "AES");

            DRMWorkaround.maybeDisableExportControls();
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

            cipher.init(Cipher.DECRYPT_MODE, keyspec);
            byte[] decrypted = cipher.doFinal(content, 0, 32);
            for (int i = 0; i < 32; i++)
                decrypted[i] ^= derived[i];
            return ECKey.fromPrivate(decrypted, compressed);
        } catch (GeneralSecurityException x) {
            throw new RuntimeException(x);
        }
    }

    private ECKey decryptEC(String normalizedPassphrase) {
        try {
            byte[] ownerEntropy = Arrays.copyOfRange(content, 0, 8);
            byte[] ownerSalt = hasLotAndSequence ? Arrays.copyOfRange(ownerEntropy, 0, 4) : ownerEntropy;

            byte[] passFactorBytes = SCrypt.generate(normalizedPassphrase.getBytes(StandardCharsets.UTF_8), ownerSalt, 16384, 8, 8, 32);
            if (hasLotAndSequence) {
                byte[] hashBytes = Bytes.concat(passFactorBytes, ownerEntropy);
                checkState(hashBytes.length == 40);
                passFactorBytes = Sha256Hash.hashTwice(hashBytes);
            }
            BigInteger passFactor = new BigInteger(1, passFactorBytes);
            ECKey k = ECKey.fromPrivate(passFactor, true);

            byte[] salt = Bytes.concat(addressHash, ownerEntropy);
            checkState(salt.length == 12);
            byte[] derived = SCrypt.generate(k.getPubKey(), salt, 1024, 1, 1, 64);
            byte[] aeskey = Arrays.copyOfRange(derived, 32, 64);

            SecretKeySpec keyspec = new SecretKeySpec(aeskey, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyspec);

            byte[] encrypted2 = Arrays.copyOfRange(content, 16, 32);
            byte[] decrypted2 = cipher.doFinal(encrypted2);
            checkState(decrypted2.length == 16);
            for (int i = 0; i < 16; i++)
                decrypted2[i] ^= derived[i + 16];

            byte[] encrypted1 = Bytes.concat(Arrays.copyOfRange(content, 8, 16), Arrays.copyOfRange(decrypted2, 0, 8));
            byte[] decrypted1 = cipher.doFinal(encrypted1);
            checkState(decrypted1.length == 16);
            for (int i = 0; i < 16; i++)
                decrypted1[i] ^= derived[i];

            byte[] seed = Bytes.concat(decrypted1, Arrays.copyOfRange(decrypted2, 8, 16));
            checkState(seed.length == 24);
            BigInteger seedFactor = new BigInteger(1, Sha256Hash.hashTwice(seed));
            checkState(passFactor.signum() >= 0);
            checkState(seedFactor.signum() >= 0);
            BigInteger priv = passFactor.multiply(seedFactor).mod(ECKey.CURVE.getN());

            return ECKey.fromPrivate(priv, compressed);
        } catch (GeneralSecurityException x) {
            throw new RuntimeException(x);
        }
    }

    @Override
    public String toString() {
        return toBase58();
    }
}
