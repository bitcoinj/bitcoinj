/*
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

import com.google.protobuf.*;
import javafx.application.*;
import javafx.event.*;
import javafx.fxml.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.wallet.*;
import org.slf4j.*;
import org.spongycastle.crypto.params.*;
import wallettemplate.utils.*;

import java.time.*;
import java.util.concurrent.*;

import static wallettemplate.utils.GuiUtils.*;

public class WalletSetPasswordController {
    private static final Logger log = LoggerFactory.getLogger(WalletSetPasswordController.class);
    public PasswordField pass1, pass2;

    public ProgressIndicator progressMeter;
    public GridPane widgetGrid;
    public Button closeButton;
    public Label explanationLabel;

    public Main.OverlayUI overlayUI;
    // These params were determined empirically on a top-range (as of 2014) MacBook Pro with native scrypt support,
    // using the scryptenc command line tool from the original scrypt distribution, given a memory limit of 40mb.
    public static final Protos.ScryptParameters SCRYPT_PARAMETERS = Protos.ScryptParameters.newBuilder()
            .setP(6)
            .setR(8)
            .setN(32768)
            .setSalt(ByteString.copyFrom(KeyCrypterScrypt.randomSalt()))
            .build();

    public void initialize() {
        progressMeter.setOpacity(0);
    }

    public static Duration estimatedKeyDerivationTime = null;

    public static CompletableFuture<Duration> estimateKeyDerivationTimeMsec() {
        // This is run in the background after startup. If we haven't recorded it before, do a key derivation to see
        // how long it takes. This helps us produce better progress feedback, as on Windows we don't currently have a
        // native Scrypt impl and the Java version is ~3 times slower, plus it depends a lot on CPU speed.
        CompletableFuture<Duration> future = new CompletableFuture<>();
        new Thread(() -> {
            log.info("Doing background test key derivation");
            KeyCrypterScrypt scrypt = new KeyCrypterScrypt(SCRYPT_PARAMETERS);
            long start = System.currentTimeMillis();
            scrypt.deriveKey("test password");
            long msec = System.currentTimeMillis() - start;
            log.info("Background test key derivation took {}msec", msec);
            Platform.runLater(() -> {
                estimatedKeyDerivationTime = Duration.ofMillis(msec);
                future.complete(estimatedKeyDerivationTime);
            });
        }).start();
        return future;
    }

    @FXML
    public void setPasswordClicked(ActionEvent event) {
        if (!pass1.getText().equals(pass2.getText())) {
            informationalAlert("Passwords do not match", "Try re-typing your chosen passwords.");
            return;
        }
        String password = pass1.getText();
        // This is kind of arbitrary and we could do much more to help people pick strong passwords.
        if (password.length() < 4) {
            informationalAlert("Password too short", "You need to pick a password at least five characters or longer.");
            return;
        }

        fadeIn(progressMeter);
        fadeOut(widgetGrid);
        fadeOut(explanationLabel);
        fadeOut(closeButton);


        KeyCrypterScrypt scrypt = new KeyCrypterScrypt(SCRYPT_PARAMETERS);

        // Deriving the actual key runs on a background thread. 500msec is empirical on my laptop (actual val is more like 333 but we give padding time).
        KeyDerivationTasks tasks = new KeyDerivationTasks(scrypt, password, estimatedKeyDerivationTime) {
            @Override
            protected final void onFinish(KeyParameter aesKey, int timeTakenMsec) {
                // Write the target time to the wallet so we can make the progress bar work when entering the password.
                WalletPasswordController.setTargetTime(Duration.ofMillis(timeTakenMsec));
                // The actual encryption part doesn't take very long as most private keys are derived on demand.
                log.info("Key derived, now encrypting");
                Main.bitcoin.wallet().encrypt(scrypt, aesKey);
                log.info("Encryption done");
                informationalAlert("Wallet encrypted",
                        "You can remove the password at any time from the settings screen.");
                overlayUI.done();
            }
        };
        progressMeter.progressProperty().bind(tasks.progress);
        tasks.start();
    }

    public void closeClicked(ActionEvent event) {
        overlayUI.done();
    }
}
