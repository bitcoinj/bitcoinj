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

import org.monacoinj.core.Utils;
import org.monacoinj.crypto.MnemonicCode;
import org.monacoinj.wallet.DeterministicSeed;
import com.google.common.base.Splitter;
import com.google.common.util.concurrent.Service;
import javafx.application.Platform;
import javafx.beans.binding.BooleanBinding;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.DatePicker;
import javafx.scene.control.TextArea;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;
import wallettemplate.utils.TextFieldValidator;

import javax.annotation.Nullable;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static javafx.beans.binding.Bindings.*;
import static wallettemplate.utils.GuiUtils.checkGuiThread;
import static wallettemplate.utils.GuiUtils.informationalAlert;
import static wallettemplate.utils.WTUtils.didThrow;
import static wallettemplate.utils.WTUtils.unchecked;

public class WalletSettingsController {
    private static final Logger log = LoggerFactory.getLogger(WalletSettingsController.class);

    @FXML Button passwordButton;
    @FXML DatePicker datePicker;
    @FXML TextArea wordsArea;
    @FXML Button restoreButton;

    public Main.OverlayUI overlayUI;

    private KeyParameter aesKey;

    // Note: NOT called by FXMLLoader!
    public void initialize(@Nullable KeyParameter aesKey) {
        DeterministicSeed seed = Main.monacoin.wallet().getKeyChainSeed();
        if (aesKey == null) {
            if (seed.isEncrypted()) {
                log.info("Wallet is encrypted, requesting password first.");
                // Delay execution of this until after we've finished initialising this screen.
                Platform.runLater(() -> askForPasswordAndRetry());
                return;
            }
        } else {
            this.aesKey = aesKey;
            seed = seed.decrypt(checkNotNull(Main.monacoin.wallet().getKeyCrypter()), "", aesKey);
            // Now we can display the wallet seed as appropriate.
            passwordButton.setText("Remove password");
        }

        // Set the date picker to show the birthday of this wallet.
        Instant creationTime = Instant.ofEpochSecond(seed.getCreationTimeSeconds());
        LocalDate origDate = creationTime.atZone(ZoneId.systemDefault()).toLocalDate();
        datePicker.setValue(origDate);

        // Set the mnemonic seed words.
        final List<String> mnemonicCode = seed.getMnemonicCode();
        checkNotNull(mnemonicCode);    // Already checked for encryption.
        String origWords = Utils.SPACE_JOINER.join(mnemonicCode);
        wordsArea.setText(origWords);

        // Validate words as they are being typed.
        MnemonicCode codec = unchecked(MnemonicCode::new);
        TextFieldValidator validator = new TextFieldValidator(wordsArea, text ->
            !didThrow(() -> codec.check(Splitter.on(' ').splitToList(text)))
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
        Main.OverlayUI<WalletPasswordController> pwd = Main.instance.overlayUI("wallet_password.fxml");
        pwd.controller.aesKeyProperty().addListener((observable, old, cur) -> {
            // We only get here if the user found the right password. If they don't or they cancel, we end up back on
            // the main UI screen.
            checkGuiThread();
            Main.OverlayUI<WalletSettingsController> screen = Main.instance.overlayUI("wallet_settings.fxml");
            screen.controller.initialize(cur);
        });
    }

    public void closeClicked(ActionEvent event) {
        overlayUI.done();
    }

    public void restoreClicked(ActionEvent event) {
        // Don't allow a restore unless this wallet is presently empty. We don't want to end up with two wallets, too
        // much complexity, even though WalletAppKit will keep the current one as a backup file in case of disaster.
        if (Main.monacoin.wallet().getBalance().value > 0) {
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
                "Your wallet will now be resynced from the Monacoin network. This can take a long time for old wallets.");
        overlayUI.done();
        Main.instance.controller.restoreFromSeedAnimation();

        long birthday = datePicker.getValue().atStartOfDay().toEpochSecond(ZoneOffset.UTC);
        DeterministicSeed seed = new DeterministicSeed(Splitter.on(' ').splitToList(wordsArea.getText()), null, "", birthday);
        // Shut down monacoinj and restart it with the new seed.
        Main.monacoin.addListener(new Service.Listener() {
            @Override
            public void terminated(Service.State from) {
                Main.instance.setupWalletKit(seed);
                Main.monacoin.startAsync();
            }
        }, Platform::runLater);
        Main.monacoin.stopAsync();
    }


    public void passwordButtonClicked(ActionEvent event) {
        if (aesKey == null) {
            Main.instance.overlayUI("wallet_set_password.fxml");
        } else {
            Main.monacoin.wallet().decrypt(aesKey);
            informationalAlert("Wallet decrypted", "A password will no longer be required to send money or edit settings.");
            passwordButton.setText("Set password");
            aesKey = null;
        }
    }
}
