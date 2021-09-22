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

import javafx.application.Platform;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import com.google.common.primitives.Longs;
import com.google.protobuf.ByteString;
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
import org.bitcoinj.walletfx.application.WalletApplication;
import org.bitcoinj.walletfx.overlay.OverlayController;
import org.bitcoinj.walletfx.overlay.OverlayableStackPaneController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bitcoinj.walletfx.utils.KeyDerivationTasks;

import java.time.Duration;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.bitcoinj.walletfx.utils.GuiUtils.*;

/**
 * User interface for entering a password on demand, e.g. to send money. Also used when encrypting a wallet. Shows a
 * progress meter as we scrypt the password.
 */
public class WalletPasswordController implements OverlayController<WalletPasswordController> {
    private static final Logger log = LoggerFactory.getLogger(WalletPasswordController.class);

    @FXML HBox buttonsBox;
    @FXML PasswordField pass1;
    @FXML ImageView padlockImage;
    @FXML ProgressIndicator progressMeter;
    @FXML GridPane widgetGrid;
    @FXML Label explanationLabel;

    private WalletApplication app;
    private OverlayableStackPaneController rootController;
    private OverlayableStackPaneController.OverlayUI<? extends OverlayController<WalletPasswordController>> overlayUI;

    private SimpleObjectProperty<KeyParameter> aesKey = new SimpleObjectProperty<>();

    @Override
    public void initOverlay(OverlayableStackPaneController overlayableStackPaneController, OverlayableStackPaneController.OverlayUI<? extends OverlayController<WalletPasswordController>> ui) {
        rootController = overlayableStackPaneController;
        overlayUI = ui;
    }

    public void initialize() {
        app = WalletApplication.instance();
        progressMeter.setOpacity(0);
        Platform.runLater(pass1::requestFocus);
    }

    @FXML void confirmClicked(ActionEvent event) {
        String password = pass1.getText();
        if (password.isEmpty() || password.length() < 4) {
            informationalAlert("Bad password", "The password you entered is empty or too short.");
            return;
        }

        final KeyCrypterScrypt keyCrypter = (KeyCrypterScrypt) app.walletAppKit().wallet().getKeyCrypter();
        checkNotNull(keyCrypter);   // We should never arrive at this GUI if the wallet isn't actually encrypted.
        KeyDerivationTasks tasks = new KeyDerivationTasks(keyCrypter, password, getTargetTime()) {
            @Override
            protected final void onFinish(KeyParameter aesKey, int timeTakenMsec) {
                checkGuiThread();
                if (app.walletAppKit().wallet().checkAESKey(aesKey)) {
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

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public static final String TAG = WalletPasswordController.class.getName() + ".target-time";

    // Writes the given time to the wallet as a tag so we can find it again in this class.
    public static void setTargetTime(Duration targetTime) {
        ByteString bytes = ByteString.copyFrom(Longs.toByteArray(targetTime.toMillis()));
        WalletApplication.instance().walletAppKit().wallet().setTag(TAG, bytes);
    }

    // Reads target time or throws if not set yet (should never happen).
    public static Duration getTargetTime() throws IllegalArgumentException {
        return Duration.ofMillis(Longs.fromByteArray(WalletApplication.instance().walletAppKit().wallet().getTag(TAG).toByteArray()));
    }
}
