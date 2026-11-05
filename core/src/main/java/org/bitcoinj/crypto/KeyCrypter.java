/*
 * Copyright 2013 Jim Burton.
 *
 * Licensed under the MIT license (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    https://opensource.org/license/mit/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * <p>A KeyCrypter can be used to encrypt and decrypt a message. The sequence of events to encrypt and then decrypt
 * a message are as follows:</p>
 *
 * <p>(1) Ask the user for a password. deriveKey() is then called to create an KeyParameter. This contains the AES
 * key that will be used for encryption.</p>
 * <p>(2) Encrypt the message using encrypt(), providing the message bytes and the KeyParameter from (1). This returns
 * an EncryptedData which contains the encryptedPrivateKey bytes and an initialisation vector.</p>
 * <p>(3) To decrypt an EncryptedData, repeat step (1) to get a KeyParameter, then call decrypt().</p>
 *
 * <p>There can be different algorithms used for encryption/ decryption so the getUnderstoodEncryptionType is used
 * to determine whether any given KeyCrypter can understand the type of encrypted data you have.</p>
 */
public interface KeyCrypter {

    /**
     * Return the EncryptionType enum value which denotes the type of encryption/ decryption that this KeyCrypter
     * can understand.
     */
    EncryptionType getUnderstoodEncryptionType();

    /**
     * Create an AESKey (which typically contains an AES key)
     * @param password
     * @return AESKey which typically contains the AES key to use for encrypting and decrypting
     * @throws KeyCrypterException
     */
    AesKey deriveKey(CharSequence password) throws KeyCrypterException;

    /**
     * Decrypt the provided encrypted bytes, converting them into unencrypted bytes.
     *
     * @throws KeyCrypterException if decryption was unsuccessful.
     */
    byte[] decrypt(EncryptedData encryptedBytesToDecode, AesKey aesKey) throws KeyCrypterException;

    /**
     * Encrypt the supplied bytes, converting them into ciphertext.
     *
     * @return encryptedPrivateKey An encryptedPrivateKey containing the encrypted bytes and an initialisation vector.
     * @throws KeyCrypterException if encryption was unsuccessful
     */
    EncryptedData encrypt(byte[] plainBytes, AesKey aesKey) throws KeyCrypterException;

    /**
     * Type of encryption used by a KeyCrypter.
     */
    enum EncryptionType {
        /** No encryption */
        UNENCRYPTED,
        /** All keys are encrypted with a passphrase-based KDF of scrypt and AES encryption */
        ENCRYPTED_SCRYPT_AES;
    }

    /**
     * Parameters for {@code KeyCrypter} implementation using the <b>scrypt</b> key derivation function.
     * The default values are taken from <a href="http://www.tarsnap.com/scrypt/scrypt-slides.pdf">scrypt-slides.pdf</a>.
     * They can be increased - {@code n} is the number of iterations performed and
     * {@code r} and {@code p} can be used to tweak the algorithm.
     * @see <a href="http://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors">What are optimal scrypt work factors?</a>
     */
    class ScryptParameters {
        public static final int DEFAULT_N = 131072;
        public static final int DEFAULT_R = 8;
        public static final int DEFAULT_P = 1;
        private final byte[] salt;
        private final int n;
        private final int r;
        private final int p;

        /**
         * Default parameters for <b>scrypt</b> parameters.
         */
        public ScryptParameters() {
            this(KeyCrypterScrypt.randomSalt(), DEFAULT_N, DEFAULT_R, DEFAULT_P);
        }

        /**
         * Canonical constructor for for <b>scrypt</b> parameters.
         * @param salt salt bytes, should be of length 8.
         * @param n General work factor, iteration count
         * @param r Blocksize in use for underlying hash; fine-tunes the relative memory-cost
         * @param p Parallelization factor; fine-tunes the relative cpu-cost
         */
        public ScryptParameters(byte[] salt, long n, int r, int p) {
            this.salt = Objects.requireNonNull(salt).clone();   // defensive copy
            this.n = Math.toIntExact(n);
            this.r = r;
            this.p = p;
        }

        /**
         * Get default parameters, overriding {@code n}.
         * @param n General work factor, iteration count
         * @return default parameters, with the value of {@code n} overridden.
         */
        public static ScryptParameters withN(int n) {
            return new ScryptParameters(KeyCrypterScrypt.randomSalt(), n, DEFAULT_R, DEFAULT_P);
        }

        /**
         * Get default parameters, overriding {@code p}.
         * @param p Parallelization factor; fine-tunes the relative cpu-cost
         * @return default parameters, with the value of {@code p} overridden.
         */
        public static ScryptParameters withP(int p) {
            return new ScryptParameters(KeyCrypterScrypt.randomSalt(), DEFAULT_N, DEFAULT_R, p);
        }

        /**
         * Get the salt.
         * @return salt
         */
        public byte[] salt() {
            return salt.clone();  // defensive-copy
        }

        /**
         * General work factor, iteration count.
         * @return iteration count
         */
        public int n() {
            return n;
        }

        /**
         * blocksize in use for underlying hash; fine-tunes the relative memory-cost.
         * @return blocksize
         */
        public int r() {
            return r;
        }

        /**
         * Parallelization factor; fine-tunes the relative cpu-cost.
         * @return parallelization factor
         */
        public int p() {
            return p;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof ScryptParameters)) return false;
            ScryptParameters that = (ScryptParameters) o;
            return n == that.n && r == that.r && p == that.p && Objects.deepEquals(salt, that.salt);
        }

        @Override
        public int hashCode() {
            return Objects.hash(Arrays.hashCode(salt), n, r, p);
        }
    }
}
