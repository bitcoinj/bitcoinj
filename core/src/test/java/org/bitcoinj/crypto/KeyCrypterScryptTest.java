/**
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

import org.bitcoinj.core.Utils;
import org.bitcoinj.utils.BriefLogFormatter;
import com.google.protobuf.ByteString;

import org.bitcoinj.wallet.Protos;
import org.bitcoinj.wallet.Protos.ScryptParameters;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

import static org.junit.Assert.*;

public class KeyCrypterScryptTest {

    private static final Logger log = LoggerFactory.getLogger(KeyCrypterScryptTest.class);

    // Nonsense bytes for encryption test.
    private static final byte[] TEST_BYTES1 = {0, -101, 2, 103, -4, 105, 6, 107, 8, -109, 10, 111, -12, 113, 14, -115, 16, 117, -18, 119, 20, 121, 22, 123, -24, 125, 26, 127, -28, 29, -30, 31};

    private static final CharSequence PASSWORD1 = "aTestPassword";
    private static final CharSequence PASSWORD2 = "0123456789";

    private static final CharSequence WRONG_PASSWORD = "thisIsTheWrongPassword";

    private ScryptParameters scryptParameters;

    @Before
    public void setUp() throws Exception {
        byte[] salt = new byte[KeyCrypterScrypt.SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        Protos.ScryptParameters.Builder scryptParametersBuilder = Protos.ScryptParameters.newBuilder().setSalt(ByteString.copyFrom(salt));
        scryptParameters = scryptParametersBuilder.build();

        BriefLogFormatter.init();
    }

    @Test
    public void testKeyCrypterGood1() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(scryptParameters);

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
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(scryptParameters);

        System.out.print("EncrypterDecrypterTest: Trying random UUIDs for plainText and passwords :");
        int numberOfTests = 16;
        for (int i = 0; i < numberOfTests; i++) {
            // Create a UUID as the plaintext and use another for the password.
            String plainText = UUID.randomUUID().toString();
            CharSequence password = UUID.randomUUID().toString();

            EncryptedData data = keyCrypter.encrypt(plainText.getBytes(), keyCrypter.deriveKey(password));

            assertNotNull(data);

            byte[] reconstructedPlainBytes = keyCrypter.decrypt(data,keyCrypter.deriveKey(password));
            assertEquals(Utils.HEX.encode(plainText.getBytes()), Utils.HEX.encode(reconstructedPlainBytes));
            System.out.print('.');
        }
        System.out.println(" Done.");
    }

    @Test
    public void testKeyCrypterWrongPassword() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(scryptParameters);

        // create a longer encryption string
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            builder.append(i).append(" The quick brown fox");
        }

        EncryptedData data = keyCrypter.encrypt(builder.toString().getBytes(), keyCrypter.deriveKey(PASSWORD2));
        assertNotNull(data);

        try {
            keyCrypter.decrypt(data, keyCrypter.deriveKey(WRONG_PASSWORD));
            // TODO: This test sometimes fails due to relying on padding.
            fail("Decrypt with wrong password did not throw exception");
        } catch (KeyCrypterException ede) {
            assertTrue(ede.getMessage().contains("Could not decrypt"));
        }
    }

    @Test
    public void testEncryptDecryptBytes1() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(scryptParameters);

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
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(scryptParameters);

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
