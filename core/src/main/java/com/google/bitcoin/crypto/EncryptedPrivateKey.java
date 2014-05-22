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

import java.util.Arrays;

/**
 * <p>An EncryptedPrivateKey contains the information produced after encrypting the private key bytes of an ECKey.</p>
 *
 * <p>It contains two member variables - initialisationVector and encryptedPrivateBytes. The initialisationVector is
 * a randomly chosen list of bytes that were used to initialise the AES block cipher when the private key bytes were encrypted.
 * You need these for decryption. The encryptedPrivateBytes are the result of AES encrypting the private keys using
 * an AES key that is derived from a user entered password. You need the password to recreate the AES key in order
 * to decrypt these bytes.</p>
 */
public class EncryptedPrivateKey {

    private byte[] initialisationVector = null;
    private byte[] encryptedPrivateBytes = null;

    /**
     * Cloning constructor.
     * @param encryptedPrivateKey EncryptedPrivateKey to clone.
     */
    public EncryptedPrivateKey(EncryptedPrivateKey encryptedPrivateKey) {
        setInitialisationVector(encryptedPrivateKey.getInitialisationVector());
        setEncryptedPrivateBytes(encryptedPrivateKey.getEncryptedBytes());
    }

    /**
     * @param initialisationVector
     * @param encryptedPrivateKeys
     */
    public EncryptedPrivateKey(byte[] initialisationVector, byte[] encryptedPrivateKeys) {
        setInitialisationVector(initialisationVector);
        setEncryptedPrivateBytes(encryptedPrivateKeys);
    }

    public byte[] getInitialisationVector() {
        return initialisationVector;
    }

    /**
     * Set the initialisationVector, cloning the bytes.
     *
     * @param initialisationVector
     */
    public void setInitialisationVector(byte[] initialisationVector) {
        if (initialisationVector == null) {
            this.initialisationVector = null;
            return;
        }

        byte[] cloneIV = new byte[initialisationVector.length];
        System.arraycopy(initialisationVector, 0, cloneIV, 0, initialisationVector.length);

        this.initialisationVector = cloneIV;
    }

    public byte[] getEncryptedBytes() {
        return encryptedPrivateBytes;
    }

    /**
     * Set the encrypted private key bytes, cloning them.
     *
     * @param encryptedPrivateBytes
     */
    public void setEncryptedPrivateBytes(byte[] encryptedPrivateBytes) {
        if (encryptedPrivateBytes == null) {
            this.encryptedPrivateBytes = null;
            return;
        }

        this.encryptedPrivateBytes = Arrays.copyOf(encryptedPrivateBytes, encryptedPrivateBytes.length);
    }

    @Override
    public EncryptedPrivateKey clone() {
        return new EncryptedPrivateKey(getInitialisationVector(), getEncryptedBytes());
    }

    @Override
    public int hashCode() {
        return com.google.common.base.Objects.hashCode(encryptedPrivateBytes, initialisationVector);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final EncryptedPrivateKey other = (EncryptedPrivateKey) obj;

        return com.google.common.base.Objects.equal(this.initialisationVector, other.initialisationVector)
                && com.google.common.base.Objects.equal(this.encryptedPrivateBytes, other.encryptedPrivateBytes);
    }

    @Override
    public String toString() {
        return "EncryptedPrivateKey [initialisationVector=" + Arrays.toString(initialisationVector) + ", encryptedPrivateKey=" + Arrays.toString(encryptedPrivateBytes) + "]";
    }

    /**
     * Clears all the EncryptedPrivateKey contents from memory (overwriting all data including PRIVATE KEYS).
     * WARNING - this method irreversibly deletes the private key information.
     */
    public void clear() {
        if (encryptedPrivateBytes != null) {
            Arrays.fill(encryptedPrivateBytes, (byte)0);
        }
        if (initialisationVector != null) {
            Arrays.fill(initialisationVector, (byte)0);
        }
    }
}
