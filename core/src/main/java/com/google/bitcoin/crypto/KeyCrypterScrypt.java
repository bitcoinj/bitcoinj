/**
 * Copyright 2013 Jim Burton.
 *
 * Licensed under the MIT license (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://opensource.org/licenses/mit-license.php
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.bitcoin.crypto;

import com.google.protobuf.ByteString;
import com.lambdaworks.crypto.SCrypt;
import org.bitcoinj.wallet.Protos;
import org.bitcoinj.wallet.Protos.ScryptParameters;
import org.bitcoinj.wallet.Protos.Wallet.EncryptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import java.io.Serializable;
import java.security.SecureRandom;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>This class encrypts and decrypts byte arrays and strings using scrypt as the
 * key derivation function and AES for the encryption.</p>
 *
 * <p>You can use this class to:</p>
 *
 * <p>1) Using a user password, create an AES key that can encrypt and decrypt your private keys.
 * To convert the password to the AES key, scrypt is used. This is an algorithm resistant
 * to brute force attacks. You can use the ScryptParameters to tune how difficult you
 * want this to be generation to be.</p>
 *
 * <p>2) Using the AES Key generated above, you then can encrypt and decrypt any bytes using
 * the AES symmetric cipher. Eight bytes of salt is used to prevent dictionary attacks.</p>
 */
public class KeyCrypterScrypt implements KeyCrypter, Serializable {
    private static final Logger log = LoggerFactory.getLogger(KeyCrypterScrypt.class);
    private static final long serialVersionUID = 949662512049152670L;

    /**
     * Key length in bytes.
     */
    public static final int KEY_LENGTH = 32; // = 256 bits.

    /**
     * The size of an AES block in bytes.
     * This is also the length of the initialisation vector.
     */
    public static final int BLOCK_LENGTH = 16;  // = 128 bits.

    /**
     * The length of the salt used.
     */
    public static final int SALT_LENGTH = 8;

    private static final transient SecureRandom secureRandom = new SecureRandom();

    // Scrypt parameters.
    private final transient ScryptParameters scryptParameters;

    /**
     * Encryption/ Decryption using default parameters and a random salt
     */
    public KeyCrypterScrypt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        Protos.ScryptParameters.Builder scryptParametersBuilder = Protos.ScryptParameters.newBuilder().setSalt(ByteString.copyFrom(salt));
        this.scryptParameters = scryptParametersBuilder.build();
    }

    /**
     * Encryption/ Decryption using specified Scrypt parameters.
     *
     * @param scryptParameters ScryptParameters to use
     * @throws NullPointerException if the scryptParameters or any of its N, R or P is null.
     */
    public KeyCrypterScrypt(ScryptParameters scryptParameters) {
        this.scryptParameters = checkNotNull(scryptParameters);
        // Check there is a non-empty salt.
        // (Some early MultiBit wallets has a missing salt so it is not a hard fail).
        if (scryptParameters.getSalt() == null
                || scryptParameters.getSalt().toByteArray() == null
                || scryptParameters.getSalt().toByteArray().length == 0) {
            log.warn("You are using a ScryptParameters with no salt. Your encryption may be vulnerable to a dictionary attack.");
        }
    }

    /**
     * Generate AES key.
     *
     * This is a very slow operation compared to encrypt/ decrypt so it is normally worth caching the result.
     *
     * @param password    The password to use in key generation
     * @return            The KeyParameter containing the created AES key
     * @throws            KeyCrypterException
     */
    @Override
    public KeyParameter deriveKey(CharSequence password) throws KeyCrypterException {
        byte[] passwordBytes = null;
        try {
            passwordBytes = convertToByteArray(password);
            byte[] salt = new byte[0];
            if ( scryptParameters.getSalt() != null) {
                salt = scryptParameters.getSalt().toByteArray();
            } else {
                // Warn the user that they are not using a salt.
                // (Some early MultiBit wallets had a blank salt).
                log.warn("You are using a ScryptParameters with no salt. Your encryption may be vulnerable to a dictionary attack.");
            }

            byte[] keyBytes = SCrypt.scrypt(passwordBytes, salt, (int) scryptParameters.getN(), scryptParameters.getR(), scryptParameters.getP(), KEY_LENGTH);
            return new KeyParameter(keyBytes);
        } catch (Exception e) {
            throw new KeyCrypterException("Could not generate key from password and salt.", e);
        } finally {
            // Zero the password bytes.
            if (passwordBytes != null) {
                java.util.Arrays.fill(passwordBytes, (byte) 0);
            }
        }
    }

    /**
     * Password based encryption using AES - CBC 256 bits.
     */
    @Override
    public EncryptedPrivateKey encrypt(byte[] plainBytes, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(plainBytes);
        checkNotNull(aesKey);

        try {
            // Generate iv - each encryption call has a different iv.
            byte[] iv = new byte[BLOCK_LENGTH];
            secureRandom.nextBytes(iv);

            ParametersWithIV keyWithIv = new ParametersWithIV(aesKey, iv);

            // Encrypt using AES.
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
            cipher.init(true, keyWithIv);
            byte[] encryptedBytes = new byte[cipher.getOutputSize(plainBytes.length)];
            int length = cipher.processBytes(plainBytes, 0, plainBytes.length, encryptedBytes, 0);

            cipher.doFinal(encryptedBytes, length);

            return new EncryptedPrivateKey(iv, encryptedBytes);
        } catch (Exception e) {
            throw new KeyCrypterException("Could not encrypt bytes.", e);
        }
    }

    /**
     * Decrypt bytes previously encrypted with this class.
     *
     * @param privateKeyToDecode    The private key to decrypt
     * @param aesKey           The AES key to use for decryption
     * @return                 The decrypted bytes
     * @throws                 KeyCrypterException if bytes could not be decoded to a valid key
     */
    @Override
    public byte[] decrypt(EncryptedPrivateKey privateKeyToDecode, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(privateKeyToDecode);
        checkNotNull(aesKey);

        try {
            ParametersWithIV keyWithIv = new ParametersWithIV(new KeyParameter(aesKey.getKey()), privateKeyToDecode.getInitialisationVector());

            // Decrypt the message.
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
            cipher.init(false, keyWithIv);

            byte[] cipherBytes = privateKeyToDecode.getEncryptedBytes();
            int minimumSize = cipher.getOutputSize(cipherBytes.length);
            byte[] outputBuffer = new byte[minimumSize];
            int length1 = cipher.processBytes(cipherBytes, 0, cipherBytes.length, outputBuffer, 0);
            int length2 = cipher.doFinal(outputBuffer, length1);
            int actualLength = length1 + length2;

            byte[] decryptedBytes = new byte[actualLength];
            System.arraycopy(outputBuffer, 0, decryptedBytes, 0, actualLength);

            return decryptedBytes;
        } catch (Exception e) {
            throw new KeyCrypterException("Could not decrypt bytes", e);
        }
    }

    /**
     * Convert a CharSequence (which are UTF16) into a byte array.
     *
     * Note: a String.getBytes() is not used to avoid creating a String of the password in the JVM.
     */
    private static byte[] convertToByteArray(CharSequence charSequence) {
        checkNotNull(charSequence);

        byte[] byteArray = new byte[charSequence.length() << 1];
        for(int i = 0; i < charSequence.length(); i++) {
            int bytePosition = i << 1;
            byteArray[bytePosition] = (byte) ((charSequence.charAt(i)&0xFF00)>>8);
            byteArray[bytePosition + 1] = (byte) (charSequence.charAt(i)&0x00FF);
        }
        return byteArray;
    }

    public ScryptParameters getScryptParameters() {
        return scryptParameters;
    }

    /**
     * Return the EncryptionType enum value which denotes the type of encryption/ decryption that this KeyCrypter
     * can understand.
     */
    @Override
    public EncryptionType getUnderstoodEncryptionType() {
        return EncryptionType.ENCRYPTED_SCRYPT_AES;
    }

    @Override
    public String toString() {
        return "Scrypt/AES";
    }

    @Override
    public int hashCode() {
        return com.google.common.base.Objects.hashCode(scryptParameters);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final KeyCrypterScrypt other = (KeyCrypterScrypt) obj;

        return com.google.common.base.Objects.equal(this.scryptParameters, other.scryptParameters);
    }
}
