/*
 * Copyright 2013 Jim Burton.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.Random;
import java.util.UUID;

import org.bitcoinj.core.Utils;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyCrypterScryptTest {

    private static final Logger log = LoggerFactory.getLogger(KeyCrypterScryptTest.class);

    // Nonsense bytes for encryption test.
    private static final byte[] TEST_BYTES1 = {0, -101, 2, 103, -4, 105, 6, 107, 8, -109, 10, 111, -12, 113, 14, -115, 16, 117, -18, 119, 20, 121, 22, 123, -24, 125, 26, 127, -28, 29, -30, 31};

    private static final int SCRYPT_ITERATIONS = 256;
    private static final CharSequence PASSWORD1 = "aTestPassword";
    private static final CharSequence PASSWORD2 = "0123456789";
    private static final CharSequence WRONG_PASSWORD = "thisIsTheWrongPassword";
    private static final CharSequence WRONG_PASSWORD2 = "anotherWrongPassword";

    private KeyCrypterScrypt keyCrypter;

    @Before
    public void setUp() throws Exception {
        keyCrypter = new KeyCrypterScrypt(SCRYPT_ITERATIONS);
    }

    @Test
    public void testKeyCrypterGood1() throws KeyCrypterException {
        // Encrypt.
        EncryptedData data = keyCrypter.encrypt(TEST_BYTES1, keyCrypter.deriveKey(PASSWORD1));
        assertNotNull(data);

        // Decrypt.
        byte[] reborn = keyCrypter.decrypt(data, keyCrypter.deriveKey(PASSWORD1));
        log.debug("Original: " + Utils.HEX.encode(TEST_BYTES1));
        log.debug("Reborn  : " + Utils.HEX.encode(reborn));
        assertEquals(Utils.HEX.encode(TEST_BYTES1), Utils.HEX.encode(reborn));
    }

    /**
     * Test with random plain text strings and random passwords.
     * UUIDs are used and hence will only cover hex characters (and the separator hyphen).
     * @throws KeyCrypterException
     */
    @Test
    public void testKeyCrypterGood2() {
        // Trying random UUIDs for plainText and passwords.
        int numberOfTests = 16;
        for (int i = 0; i < numberOfTests; i++) {
            // Create a UUID as the plaintext and use another for the password.
            String plainText = UUID.randomUUID().toString();
            CharSequence password = UUID.randomUUID().toString();

            EncryptedData data = keyCrypter.encrypt(plainText.getBytes(), keyCrypter.deriveKey(password));

            assertNotNull(data);

            byte[] reconstructedPlainBytes = keyCrypter.decrypt(data,keyCrypter.deriveKey(password));
            assertEquals(Utils.HEX.encode(plainText.getBytes()), Utils.HEX.encode(reconstructedPlainBytes));
        }
    }

    @Test
    public void testKeyCrypterWrongPassword() throws KeyCrypterException {
        // create a longer encryption string
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            builder.append(i).append(" The quick brown fox");
        }

        byte[] plainText = builder.toString().getBytes();
        EncryptedData data = keyCrypter.encrypt(plainText, keyCrypter.deriveKey(PASSWORD2));
        assertNotNull(data);

        try {
            // This sometimes doesn't throw due to relying on padding...
            byte[] cipherText = keyCrypter.decrypt(data, keyCrypter.deriveKey(WRONG_PASSWORD));
            // ...so we also check for length, because that's the 2nd level test we're doing e.g. in ECKey/DeterministicKey...
            assertNotEquals(plainText.length, cipherText.length);
            // ...and then try with another wrong password again.
            keyCrypter.decrypt(data, keyCrypter.deriveKey(WRONG_PASSWORD2));
            // Note: it can still fail, but it should be extremely rare.
            fail("Decrypt with wrong password did not throw exception");
        } catch (KeyCrypterException.InvalidCipherText x) {
            // expected
        }
    }

    @Test
    public void testEncryptDecryptBytes1() throws KeyCrypterException {
        // Encrypt bytes.
        EncryptedData data = keyCrypter.encrypt(TEST_BYTES1, keyCrypter.deriveKey(PASSWORD1));
        assertNotNull(data);
        log.debug("\nEncrypterDecrypterTest: cipherBytes = \nlength = " + data.encryptedBytes.length + "\n---------------\n" + Utils.HEX.encode(data.encryptedBytes) + "\n---------------\n");

        byte[] rebornPlainBytes = keyCrypter.decrypt(data, keyCrypter.deriveKey(PASSWORD1));

        log.debug("Original: " + Utils.HEX.encode(TEST_BYTES1));
        log.debug("Reborn1 : " + Utils.HEX.encode(rebornPlainBytes));
        assertEquals(Utils.HEX.encode(TEST_BYTES1), Utils.HEX.encode(rebornPlainBytes));
    }

    @Test
    public void testEncryptDecryptBytes2() throws KeyCrypterException {
        // Encrypt random bytes of various lengths up to length 50.
        Random random = new Random();

        for (int i = 0; i < 50; i++) {
            byte[] plainBytes = new byte[i];
            random.nextBytes(plainBytes);

            EncryptedData data = keyCrypter.encrypt(plainBytes, keyCrypter.deriveKey(PASSWORD1));
            assertNotNull(data);
            //log.debug("\nEncrypterDecrypterTest: cipherBytes = \nlength = " + cipherBytes.length + "\n---------------\n" + Utils.HEX.encode(cipherBytes) + "\n---------------\n");

            byte[] rebornPlainBytes = keyCrypter.decrypt(data, keyCrypter.deriveKey(PASSWORD1));

            log.debug("Original: (" + i + ") " + Utils.HEX.encode(plainBytes));
            log.debug("Reborn1 : (" + i + ") " + Utils.HEX.encode(rebornPlainBytes));
            assertEquals(Utils.HEX.encode(plainBytes), Utils.HEX.encode(rebornPlainBytes));
        }
    }
}
