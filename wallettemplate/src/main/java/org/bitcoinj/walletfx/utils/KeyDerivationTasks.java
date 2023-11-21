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

package org.bitcoinj.walletfx.utils;

import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.concurrent.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nullable;
import java.time.Duration;

import static org.bitcoinj.walletfx.utils.GuiUtils.checkGuiThread;

/**
 * Background tasks for pumping a progress meter and deriving an AES key using scrypt.
 */
public class KeyDerivationTasks {
    private static final Logger log = LoggerFactory.getLogger(KeyDerivationTasks.class);
    // 60fps would require a 16 millisecond value here.
    private static final Duration PROGRESS_UPDATE_INTERVAL = Duration.ofMillis(20);

    public final Task<AesKey> keyDerivationTask;
    public final ReadOnlyDoubleProperty progress;

    private final Task<Void> progressTask;

    private volatile int timeTakenMsec = -1;

    public KeyDerivationTasks(KeyCrypterScrypt scrypt, String password, @Nullable Duration targetTime) {
        keyDerivationTask = new Task<>() {
            @Override
            protected AesKey call() throws Exception {
                long start = System.currentTimeMillis();
                try {
                    log.info("Started key derivation");
                    AesKey result = scrypt.deriveKey(password);
                    timeTakenMsec = (int) (System.currentTimeMillis() - start);
                    log.info("Key derivation done in {}ms", timeTakenMsec);
                    return result;
                } catch (Throwable e) {
                    log.error("Exception during key derivation", e);
                    throw e;
                }
            }
        };

        // And the fake progress meter ... if the vals were calculated correctly progress bar should reach 100%
        // a brief moment after the keys were derived successfully.
        progressTask = new Task<>() {
            private AesKey aesKey;

            @Override
            protected Void call() throws Exception {
                if (targetTime != null) {
                    long startTime = System.currentTimeMillis();
                    long curTime;
                    long targetTimeMillis = targetTime.toMillis();
                    while ((curTime = System.currentTimeMillis()) < startTime + targetTimeMillis) {
                        double progress = (curTime - startTime) / (double) targetTimeMillis;
                        updateProgress(progress, 1.0);

                        Thread.sleep(PROGRESS_UPDATE_INTERVAL.toMillis());
                    }
                    // Wait for the encryption thread before switching back to main UI.
                    updateProgress(1.0, 1.0);
                } else {
                    updateProgress(-1, -1);
                }
                aesKey = keyDerivationTask.get();
                return null;
            }

            @Override
            protected void succeeded() {
                checkGuiThread();
                onFinish(aesKey, timeTakenMsec);
            }
        };
        progress = progressTask.progressProperty();
    }

    public void start() {
        new Thread(keyDerivationTask, "Key derivation").start();
        new Thread(progressTask, "Progress ticker").start();
    }

    protected void onFinish(AesKey aesKey, int timeTakenMsec) {
    }
}
