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

import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.DeterministicSeed;
import com.google.common.base.Splitter;
import com.google.common.util.concurrent.Service;
import javafx.application.Platform;
import javafx.beans.binding.BooleanBinding;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.DatePicker;
import javafx.scene.control.TextArea;
import org.bitcoinj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bitcoinj.walletfx.utils.TextFieldValidator;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static javafx.beans.binding.Bindings.*;
import static org.bitcoinj.walletfx.utils.GuiUtils.checkGuiThread;
import static org.bitcoinj.walletfx.utils.GuiUtils.informationalAlert;
import static org.bitcoinj.walletfx.utils.WTUtils.didThrow;
import static org.bitcoinj.walletfx.utils.WTUtils.unchecked;

@Singleton
public class WalletSettingsController implements OverlayWindowController {
    private static final Logger log = LoggerFactory.getLogger(WalletSettingsController.class);

    @FXML private Button passwordButton;
    @FXML private DatePicker datePicker;
    @FXML private TextArea wordsArea;
    @FXML private Button restoreButton;

    private OverlayableWindowController.OverlayUI overlayUI;

    private KeyParameter aesKey;

    private final WalletFxApp app;
    private final WalletMainWindowController mainWindow;

    public WalletSettingsController(WalletFxApp app, WalletMainWindowController mainWindow) {
        this.app = app;
        this.mainWindow = mainWindow;
    }

    @Override
    public OverlayableWindowController.OverlayUI getOverlayUI() {
        return overlayUI;
    }

    @Override
    public void setOverlayUI(OverlayableWindowController.OverlayUI ui) {
        overlayUI = ui;
    }

    // Note: NOT called by FXMLLoader!
    public void initialize(@Nullable KeyParameter aesKey) {
        Wallet wallet = app.getWallet();

        Instant creationTime;
        String origWords;
        if (wallet.isWatching()) {
            creationTime = Instant.ofEpochSecond(wallet.getWatchingKey().getCreationTimeSeconds());
            origWords = wallet.getWatchingKey().serializePubB58(app.getNetParams(),  Script.ScriptType.P2PKH);
        } else {
            DeterministicSeed seed = app.getWallet().getKeyChainSeed();
            if (aesKey == null) {
                if (seed.isEncrypted()) {
                    log.info("Wallet is encrypted, requesting password first.");
                    // Delay execution of this until after we've finished initialising this screen.
                    Platform.runLater(this::askForPasswordAndRetry);
                    return;
                }
            } else {
                this.aesKey = aesKey;
                seed = seed.decrypt(checkNotNull(app.getWallet().getKeyCrypter()), "", aesKey);
                // Now we can display the wallet seed as appropriate.
                passwordButton.setText("Remove password");
            }

            // Set the date picker to show the birthday of this wallet.
            creationTime = Instant.ofEpochSecond(seed.getCreationTimeSeconds());

            // Set the mnemonic seed words.
            final List<String> mnemonicCode = seed.getMnemonicCode();
            checkNotNull(mnemonicCode);    // Already checked for encryption.
            origWords = Utils.SPACE_JOINER.join(mnemonicCode);

        }
        LocalDate origDate = creationTime.atZone(getZoneId()).toLocalDate();
        datePicker.setValue(origDate);
        wordsArea.setText(origWords);


        // Validate words as they are being typed.
        MnemonicCode codec = unchecked(MnemonicCode::new);
        TextFieldValidator validator = new TextFieldValidator(wordsArea, text ->
            !didThrow(() -> {
                if (text.startsWith("tpub")) {
                    // TODO: Maybe a little validation of the xpub string here
                } else {
                    codec.check(Splitter.on(' ').splitToList(text));
                }
            })
        );

        // Clear the date picker if the user starts editing the words, if it contained the current wallets date.
        // This forces them to set the birthday field when restoring.
        wordsArea.textProperty().addListener(o -> {
            if (origDate.equals(datePicker.getValue()))
                datePicker.setValue(null);
        });

        BooleanBinding datePickerIsInvalid = or(
                datePicker.valueProperty().isNull(),

                createBooleanBinding(() ->
                        datePicker.getValue().isAfter(LocalDate.now())
                , /* depends on */ datePicker.valueProperty())
        );

        // Don't let the user click restore if the words area contains the current wallet words, or are an invalid set,
        // or if the date field isn't set, or if it's in the future.
        restoreButton.disableProperty().bind(
                or(
                        or(
                                not(validator.valid),
                                equal(origWords, wordsArea.textProperty())
                        ),

                        datePickerIsInvalid
                )
        );

        // Highlight the date picker in red if it's empty or in the future, so the user knows why restore is disabled.
        datePickerIsInvalid.addListener((dp, old, cur) -> {
            if (cur) {
                datePicker.getStyleClass().add("validation_error");
            } else {
                datePicker.getStyleClass().remove("validation_error");
            }
        });
    }

    private void askForPasswordAndRetry() {
        OverlayableWindowController.OverlayUI<WalletPasswordController> pwd = mainWindow.overlayUI("wallet_password.fxml");
        pwd.controller.aesKeyProperty().addListener((observable, old, cur) -> {
            // We only get here if the user found the right password. If they don't or they cancel, we end up back on
            // the main UI screen.
            checkGuiThread();
            OverlayableWindowController.OverlayUI<WalletSettingsController> screen = mainWindow.overlayUI("wallet_settings.fxml");
            screen.controller.initialize(cur);
        });
    }

    public void closeClicked(ActionEvent event) {
        overlayUI.done();
    }

    public void restoreClicked(ActionEvent event) {
        // Don't allow a restore unless this wallet is presently empty. We don't want to end up with two wallets, too
        // much complexity, even though WalletAppKit will keep the current one as a backup file in case of disaster.
        if (app.getWallet().getBalance().value > 0) {
            informationalAlert("Wallet is not empty",
                    "You must empty this wallet out before attempting to restore an older one, as mixing wallets " +
                            "together can lead to invalidated backups.");
            return;
        }

        if (aesKey != null) {
            // This is weak. We should encrypt the new seed here.
            informationalAlert("Wallet is encrypted",
                    "After restore, the wallet will no longer be encrypted and you must set a new password.");
        }

        log.info("Attempting wallet restore using seed '{}' from date {}", wordsArea.getText(), datePicker.getValue());
        informationalAlert("Wallet restore in progress",
                "Your wallet will now be resynced from the Bitcoin network. This can take a long time for old wallets.");
        overlayUI.done();
        mainWindow.restoreFromSeedAnimation();

        long birthday = datePicker.getValue().atStartOfDay().toEpochSecond(ZoneOffset.of(getZoneId().getId()));

        var wordsText = wordsArea.getText();
        if (wordsText.startsWith("tpub")) {
            // It's an xpub string (temporary hack until we can redo the UI)
            log.info("preparing to restart with xpub string");
            var key = DeterministicKey.deserializeB58(wordsText, TestNet3Params.get());
            key.setCreationTimeSeconds(birthday);   // Set key creation time to speed blockchain sync
            // Shut down bitcoinj and restart it with the new key.
            app.getWalletAppKit().addListener(new Service.Listener() {
                @Override
                public void terminated(Service.State from) {
                    app.setupWalletKit(key);
                    app.getWalletAppKit().startAsync();
                }
            }, Platform::runLater);

        } else {
            log.info("preparing to restart with wallet words");
            var seed = new DeterministicSeed(Splitter.on(' ').splitToList(wordsText), null, "", birthday);
            // Shut down bitcoinj and restart it with the new seed.
            app.getWalletAppKit().addListener(new Service.Listener() {
                @Override
                public void terminated(Service.State from) {
                    app.setupWalletKit(seed);
                    app.getWalletAppKit().startAsync();
                }
            }, Platform::runLater);
        }

        app.getWalletAppKit().stopAsync();
    }
    
    public void passwordButtonClicked(ActionEvent event) {
        if (aesKey == null) {
            mainWindow.overlayUI("wallet_set_password.fxml");
        } else {
            app.getWallet().decrypt(aesKey);
            informationalAlert("Wallet decrypted", "A password will no longer be required to send money or edit settings.");
            passwordButton.setText("Set password");
            aesKey = null;
        }
    }

    private ZoneId getZoneId() {
        return ZoneId.systemDefault();
    }
}
