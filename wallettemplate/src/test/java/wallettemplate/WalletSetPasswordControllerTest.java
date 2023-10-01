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
package wallettemplate;

import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static wallettemplate.WalletSetPasswordController.SCRYPT_PARAMETERS;

public class WalletSetPasswordControllerTest {
    private static final Logger log = LoggerFactory.getLogger(WalletSetPasswordController.class);

    /**
     * Ensure key derivation time with {@link WalletSetPasswordController#SCRYPT_PARAMETERS} isn't inordinately slow.
     */
    @Test
    void keyDerivationIsNotTooSlow() {
        // Measure key derivation time with our
        Duration duration = measureKeyDerivationTime();
        assertTrue(duration.compareTo(Duration.ofSeconds(30)) < 0, "Key derivation took too long.");
    }

    /**
     * Measure key derivation time
     * @return measured duration
     */
    private static Duration measureKeyDerivationTime() {
        log.info("Doing background test key derivation");
        KeyCrypterScrypt scrypt = new KeyCrypterScrypt(SCRYPT_PARAMETERS);
        long start = System.currentTimeMillis();
        scrypt.deriveKey("test password");
        long msec = System.currentTimeMillis() - start;
        log.info("Background test key derivation took {}msec", msec);
        return Duration.ofMillis(msec);
    }
}
