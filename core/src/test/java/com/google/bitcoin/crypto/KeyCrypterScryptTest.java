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

import com.google.bitcoin.core.Utils;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.protobuf.ByteString;

import org.bitcoinj.wallet.Protos;
import org.bitcoinj.wallet.Protos.ScryptParameters;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
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
        EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(TEST_BYTES1, keyCrypter.deriveKey(PASSWORD1));
        assertNotNull(encryptedPrivateKey);

        // Decrypt.
        byte[] reborn = keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(PASSWORD1));
        log.debug("Original: " + Utils.bytesToHexString(TEST_BYTES1));
        log.debug("Reborn  : " + Utils.bytesToHexString(reborn));
        assertEquals(Utils.bytesToHexString(TEST_BYTES1), Utils.bytesToHexString(reborn));
    }

    /**
     * Test with random plain text strings and random passwords.
     * UUIDs are used and hence will only cover hex characters (and the separator hyphen).
     * @throws KeyCrypterException
     * @throws UnsupportedEncodingException
     */
    @Test
    public void testKeyCrypterGood2() throws Exception {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(scryptParameters);

        System.out.print("EncrypterDecrypterTest: Trying random UUIDs for plainText and passwords :");
        int numberOfTests = 16;
        for (int i = 0; i < numberOfTests; i++) {
            // Create a UUID as the plaintext and use another for the password.
            String plainText = UUID.randomUUID().toString();
            CharSequence password = UUID.randomUUID().toString();

            EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(plainText.getBytes(), keyCrypter.deriveKey(password));

            assertNotNull(encryptedPrivateKey);

            byte[] reconstructedPlainBytes = keyCrypter.decrypt(encryptedPrivateKey,keyCrypter.deriveKey(password));
            assertEquals(Utils.bytesToHexString(plainText.getBytes()), Utils.bytesToHexString(reconstructedPlainBytes));
            System.out.print('.');
        }
        System.out.println(" Done.");
    }

    @Test
    public void testKeyCrypterWrongPassword() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(scryptParameters);

        // create a longer encryption string
        StringBuilder stringBuffer = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            stringBuffer.append(i).append(" ").append("The quick brown fox");
        }

        EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(stringBuffer.toString().getBytes(), keyCrypter.deriveKey(PASSWORD2));
        assertNotNull(encryptedPrivateKey);

        try {
            keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(WRONG_PASSWORD));
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
        EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(TEST_BYTES1, keyCrypter.deriveKey(PASSWORD1));
        assertNotNull(encryptedPrivateKey);
        log.debug("\nEncrypterDecrypterTest: cipherBytes = \nlength = " + encryptedPrivateKey.getEncryptedBytes().length + "\n---------------\n" + Utils.bytesToHexString(encryptedPrivateKey.getEncryptedBytes()) + "\n---------------\n");

        byte[] rebornPlainBytes = keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(PASSWORD1));

        log.debug("Original: " + Utils.bytesToHexString(TEST_BYTES1));
        log.debug("Reborn1 : " + Utils.bytesToHexString(rebornPlainBytes));
        assertEquals(Utils.bytesToHexString(TEST_BYTES1), Utils.bytesToHexString(rebornPlainBytes));
    }

    @Test
    public void testEncryptDecryptBytes2() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(scryptParameters);

        // Encrypt random bytes of various lengths up to length 50.
        Random random = new Random();

        for (int i = 0; i < 50; i++) {
            byte[] plainBytes = new byte[i];
            random.nextBytes(plainBytes);

            EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(plainBytes, keyCrypter.deriveKey(PASSWORD1));
            assertNotNull(encryptedPrivateKey);
            //log.debug("\nEncrypterDecrypterTest: cipherBytes = \nlength = " + cipherBytes.length + "\n---------------\n" + Utils.bytesToHexString(cipherBytes) + "\n---------------\n");

            byte[] rebornPlainBytes = keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(PASSWORD1));

            log.debug("Original: (" + i + ") " + Utils.bytesToHexString(plainBytes));
            log.debug("Reborn1 : (" + i + ") " + Utils.bytesToHexString(rebornPlainBytes));
            assertEquals(Utils.bytesToHexString(plainBytes), Utils.bytesToHexString(rebornPlainBytes));
        }
    }
}
