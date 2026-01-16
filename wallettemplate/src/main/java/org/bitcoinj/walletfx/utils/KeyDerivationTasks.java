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

import org.jspecify.annotations.Nullable;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.concurrent.Task;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.bitcoinj.walletfx.utils.GuiUtils.checkGuiThread;

// TODO: This should be rewritten as a single JavaFX task called something like EstimatedCompletionTask<T>.
// It will be a subclass of JavaFX Task<T> and its constructor will take 2 parameters:
// 1. an estimated duration
// 2. a CompletableFuture<T>
// It's job is to update progressProperty based upon the time estimate and complete when the
// CompletableFuture completes (whether that is before or after the estimated time).
// Maybe it will have an onFinish method or maybe the caller should just use the CompletableFuture for that.
// If an onFinish is included maybe it just returns T or maybe it returns a record containing T and the actual time taken
// And maybe we can remove the use of Uninterruptibles.sleepUninterruptibly() while were at it.
/**
 * Background tasks for pumping a progress meter and deriving an AES key using scrypt.
 */
public abstract class KeyDerivationTasks {
    private static final Logger log = LoggerFactory.getLogger(KeyDerivationTasks.class);
    // 60fps would require a 16 millisecond value here.
    private static final Duration PROGRESS_UPDATE_INTERVAL = Duration.ofMillis(20);

    private final Task<AesKey> keyDerivationTask;
    public final ReadOnlyDoubleProperty progress;

    private final Task<Void> progressTask;

    private volatile int timeTakenMsec = -1;

    public KeyDerivationTasks(KeyCrypterScrypt scrypt, String password, Duration targetTime) {
        keyDerivationTask = new Task<>() {
            @Override
            protected AesKey call() {
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
                    while ((curTime = System.currentTimeMillis()) < startTime + targetTimeMillis && !keyDerivationTask.isDone()) {
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

    abstract protected void onFinish(AesKey aesKey, int timeTakenMsec);
}
