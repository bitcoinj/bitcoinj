package wallettemplate.utils;

import org.bitcoinj.crypto.KeyCrypterScrypt;
import com.google.common.util.concurrent.Uninterruptibles;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.concurrent.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

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

    public KeyDerivationTasks(KeyCrypterScrypt scrypt, String password, Duration targetTime) {
        keyDerivationTask = new Task<KeyParameter>() {
            @Override
            protected KeyParameter call() throws Exception {
                try {
                    return scrypt.deriveKey(password);
                } catch (Throwable e) {
                    e.printStackTrace();
                    throw e;
                } finally {
                    log.info("Key derivation done");
                }
            }
        };

        // And the fake progress meter ...
        progressTask = new Task<Void>() {
            private KeyParameter aesKey;

            @Override
            protected Void call() throws Exception {
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
                aesKey = keyDerivationTask.get();
                return null;
            }

            @Override
            protected void succeeded() {
                checkGuiThread();
                onFinish(aesKey);
            }
        };
        progress = progressTask.progressProperty();
    }

    public void start() {
        new Thread(keyDerivationTask, "Key derivation").start();
        new Thread(progressTask, "Progress ticker").start();
    }

    protected void onFinish(KeyParameter aesKey) {
    }
}
