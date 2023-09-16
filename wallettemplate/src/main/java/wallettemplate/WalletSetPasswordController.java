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

import com.google.protobuf.ByteString;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.layout.GridPane;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.protobuf.wallet.Protos;
import org.bitcoinj.walletfx.application.WalletApplication;
import org.bitcoinj.walletfx.overlay.OverlayController;
import org.bitcoinj.walletfx.overlay.OverlayableStackPaneController;
import org.bitcoinj.walletfx.utils.KeyDerivationTasks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

import static org.bitcoinj.walletfx.utils.GuiUtils.fadeIn;
import static org.bitcoinj.walletfx.utils.GuiUtils.fadeOut;
import static org.bitcoinj.walletfx.utils.GuiUtils.informationalAlert;

public class WalletSetPasswordController implements OverlayController<WalletSetPasswordController> {
    private static final Logger log = LoggerFactory.getLogger(WalletSetPasswordController.class);
    public PasswordField pass1, pass2;

    public ProgressIndicator progressMeter;
    public GridPane widgetGrid;
    public Button closeButton;
    public Label explanationLabel;

    private WalletApplication app;
    private OverlayableStackPaneController rootController;
    private OverlayableStackPaneController.OverlayUI<? extends OverlayController<WalletSetPasswordController>> overlayUI;
    // These params were determined empirically on a top-range (as of 2014) MacBook Pro with native scrypt support,
    // using the scryptenc command line tool from the original scrypt distribution, given a memory limit of 40mb.
    public static final Protos.ScryptParameters SCRYPT_PARAMETERS = Protos.ScryptParameters.newBuilder()
            .setP(6)
            .setR(8)
            .setN(32768)
            .setSalt(ByteString.copyFrom(KeyCrypterScrypt.randomSalt()))
            .build();

    @Override
    public void initOverlay(OverlayableStackPaneController overlayableStackPaneController, OverlayableStackPaneController.OverlayUI<? extends OverlayController<WalletSetPasswordController>> ui) {
        rootController = overlayableStackPaneController;
        overlayUI = ui;
    }

    public void initialize() {
        app = WalletApplication.instance();
        progressMeter.setOpacity(0);
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
        KeyDerivationTasks tasks = new KeyDerivationTasks(scrypt, password, WalletPasswordController.getTargetTime()) {
            @Override
            protected final void onFinish(AesKey aesKey, int timeTakenMsec) {
                // Earlier versions of this code persisted the target time to the wallet, so
                // it could initialize the progress bar more accurately when the user is entering the password.
                // The actual encryption part doesn't take very long as most private keys are derived on demand.
                log.info("Key derived, now encrypting");
                app.walletAppKit().wallet().encrypt(scrypt, aesKey);
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
