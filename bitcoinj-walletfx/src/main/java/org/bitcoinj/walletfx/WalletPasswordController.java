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

package org.bitcoinj.walletfx;

import javafx.application.Platform;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.image.ImageView;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bitcoinj.walletfx.utils.KeyDerivationTasks;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.bitcoinj.walletfx.utils.GuiUtils.*;

/**
 * User interface for entering a password on demand, e.g. to send money. Also used when encrypting a wallet. Shows a
 * progress meter as we scrypt the password.
 */
public class WalletPasswordController implements OverlayWindowController {
    private static final Logger log = LoggerFactory.getLogger(WalletPasswordController.class);

    @FXML private HBox buttonsBox;
    @FXML private PasswordField pass1;
    @FXML private ImageView padlockImage;
    @FXML private ProgressIndicator progressMeter;
    @FXML private GridPane widgetGrid;
    @FXML private Label explanationLabel;

    private OverlayableWindowController.OverlayUI overlayUI;

    private SimpleObjectProperty<KeyParameter> aesKey = new SimpleObjectProperty<>();

    private WalletFxApp app;

    public WalletPasswordController(WalletFxApp app) {
        this.app = app;
    }

    @Override
    public OverlayableWindowController.OverlayUI getOverlayUI() {
        return overlayUI;
    }

    @Override
    public void setOverlayUI(OverlayableWindowController.OverlayUI ui) {
        overlayUI = ui;
    }

    public void initialize() {
        progressMeter.setOpacity(0);
        Platform.runLater(pass1::requestFocus);
    }

    @FXML void confirmClicked(ActionEvent event) {
        String password = pass1.getText();
        if (password.isEmpty() || password.length() < 4) {
            informationalAlert("Bad password", "The password you entered is empty or too short.");
            return;
        }

        final KeyCrypterScrypt keyCrypter = (KeyCrypterScrypt) app.getWallet().getKeyCrypter();
        checkNotNull(keyCrypter);   // We should never arrive at this GUI if the wallet isn't actually encrypted.
        KeyDerivationTasks tasks = new KeyDerivationTasks(keyCrypter, password, app.getTargetTime()) {
            @Override
            protected final void onFinish(KeyParameter aesKey, int timeTakenMsec) {
                checkGuiThread();
                if (app.getWallet().checkAESKey(aesKey)) {
                    WalletPasswordController.this.aesKey.set(aesKey);
                } else {
                    log.warn("User entered incorrect password");
                    fadeOut(progressMeter);
                    fadeIn(widgetGrid);
                    fadeIn(explanationLabel);
                    fadeIn(buttonsBox);
                    informationalAlert("Wrong password",
                            "Please try entering your password again, carefully checking for typos or spelling errors.");
                }
            }
        };
        progressMeter.progressProperty().bind(tasks.progress);
        tasks.start();

        fadeIn(progressMeter);
        fadeOut(widgetGrid);
        fadeOut(explanationLabel);
        fadeOut(buttonsBox);
    }

    public void cancelClicked(ActionEvent event) {
        overlayUI.done();
    }

    public ReadOnlyObjectProperty<KeyParameter> aesKeyProperty() {
        return aesKey;
    }

}
