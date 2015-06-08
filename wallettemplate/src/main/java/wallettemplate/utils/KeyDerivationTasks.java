package wallettemplate.utils;

import org.bitcoinj.crypto.KeyCrypterScrypt;
import com.google.common.util.concurrent.Uninterruptibles;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.concurrent.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.*;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static wallettemplate.utils.GuiUtils.checkGuiThread;

/**
 * Background tasks for pumping a progress meter and deriving an AES key using scrypt.
 */
public class KeyDerivationTasks {
    private static final Logger log = LoggerFactory.getLogger(KeyDerivationTasks.class);

    public final Task<KeyParameter> keyDerivationTask;
    public final ReadOnlyDoubleProperty progress;

    private final Task<Void> progressTask;

    private volatile int timeTakenMsec = -1;

    public KeyDerivationTasks(KeyCrypterScrypt scrypt, String password, @Nullable Duration targetTime) {
        keyDerivationTask = new Task<KeyParameter>() {
            @Override
            protected KeyParameter call() throws Exception {
                long start = System.currentTimeMillis();
                try {
                    log.info("Started key derivation");
                    KeyParameter result = scrypt.deriveKey(password);
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
        progressTask = new Task<Void>() {
            private KeyParameter aesKey;

            @Override
            protected Void call() throws Exception {
                if (targetTime != null) {
                    long startTime = System.currentTimeMillis();
                    long curTime;
                    long targetTimeMillis = targetTime.toMillis();
                    while ((curTime = System.currentTimeMillis()) < startTime + targetTimeMillis) {
                        double progress = (curTime - startTime) / (double) targetTimeMillis;
                        updateProgress(progress, 1.0);

                        // 60fps would require 16msec sleep here.
                        Uninterruptibles.sleepUninterruptibly(20, TimeUnit.MILLISECONDS);
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

    protected void onFinish(KeyParameter aesKey, int timeTakenMsec) {
    }
}
