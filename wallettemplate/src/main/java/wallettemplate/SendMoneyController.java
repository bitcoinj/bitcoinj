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
import javafx.event.ActionEvent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.TransactionBroadcast;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.walletfx.application.WalletApplication;
import org.bitcoinj.walletfx.controls.BitcoinAddressValidator;
import org.bitcoinj.walletfx.overlay.OverlayController;
import org.bitcoinj.walletfx.overlay.OverlayableStackPaneController;
import org.bitcoinj.walletfx.utils.TextFieldValidator;
import org.bitcoinj.walletfx.utils.WTUtils;
import org.jspecify.annotations.Nullable;

import java.util.Objects;

import static org.bitcoinj.base.internal.Preconditions.checkState;
import static org.bitcoinj.walletfx.utils.GuiUtils.checkGuiThread;
import static org.bitcoinj.walletfx.utils.GuiUtils.crashAlert;
import static org.bitcoinj.walletfx.utils.GuiUtils.informationalAlert;

public class SendMoneyController implements OverlayController<SendMoneyController> {
    public @Nullable Button sendBtn;
    public @Nullable Button cancelBtn;
    public @Nullable TextField address;
    public @Nullable Label titleLabel;
    public @Nullable TextField amountEdit;
    public @Nullable Label btcLabel;

    private @Nullable WalletApplication app;
    private @Nullable OverlayableStackPaneController rootController;
    private OverlayableStackPaneController.@Nullable OverlayUI<? extends OverlayController<SendMoneyController>> overlayUI;

    private @Nullable TransactionBroadcast sendResult;
    private @Nullable AesKey aesKey;

    @Override
    public void initOverlay(OverlayableStackPaneController overlayableStackPaneController, OverlayableStackPaneController.OverlayUI<? extends OverlayController<SendMoneyController>> ui) {
        rootController = overlayableStackPaneController;
        overlayUI = ui;
    }

    // Called by FXMLLoader
    public void initialize() {
        app = WalletApplication.instance();
        Objects.requireNonNull(amountEdit);
        Objects.requireNonNull(address);
        Coin balance = app.walletAppKit().wallet().getBalance();
        checkState(!balance.isZero());
        new BitcoinAddressValidator(app.walletAppKit().wallet(), address, sendBtn);
        new TextFieldValidator(amountEdit, text ->
                !WTUtils.didThrow(() -> checkState(Coin.parseCoin(text).compareTo(balance) <= 0)));
        amountEdit.setText(balance.toPlainString());
        address.setPromptText(ECKey.random().toAddress(app.preferredOutputScriptType(), app.network()).toString());
    }

    public void cancel(ActionEvent event) {
        Objects.requireNonNull(overlayUI);
        overlayUI.done();
    }

    public void send(@Nullable ActionEvent event) {
        Objects.requireNonNull(app);
        Objects.requireNonNull(amountEdit);
        Objects.requireNonNull(address);
        Objects.requireNonNull(sendBtn);
        Objects.requireNonNull(btcLabel);
        Objects.requireNonNull(overlayUI);
        // Address exception cannot happen as we validated it beforehand.
        try {
            Coin amount = Coin.parseCoin(amountEdit.getText());
            Address destination = app.walletAppKit().wallet().parseAddress(address.getText());
            SendRequest req;
            if (amount.equals(app.walletAppKit().wallet().getBalance()))
                req = SendRequest.emptyWallet(destination);
            else
                req = SendRequest.to(destination, amount);
            req.aesKey = aesKey;
            // Don't make the user wait for confirmations for now, as the intention is they're sending it
            // their own money!
            req.allowUnconfirmed();
            sendResult = app.walletAppKit().wallet().sendCoins(req);
            sendResult.awaitRelayed().whenComplete((result, t) -> {
                Objects.requireNonNull(overlayUI);
                Objects.requireNonNull(overlayUI);
                if (t == null) {
                    Platform.runLater(() -> {Objects.requireNonNull(overlayUI); overlayUI.done();});
                } else {
                    // We died trying to empty the wallet.
                    crashAlert(t);
                }
            });
            sendResult.transaction().getConfidence().addEventListener((tx, reason) -> {
                if (reason == TransactionConfidence.Listener.ChangeReason.SEEN_PEERS)
                    updateTitleForBroadcast();
            });
            sendBtn.setDisable(true);
            address.setDisable(true);
            ((HBox)amountEdit.getParent()).getChildren().remove(amountEdit);
            ((HBox)btcLabel.getParent()).getChildren().remove(btcLabel);
            updateTitleForBroadcast();
        } catch (InsufficientMoneyException e) {
            informationalAlert("Could not empty the wallet",
                    "You may have too little money left in the wallet to make a transaction.");
            overlayUI.done();
        } catch (ECKey.KeyIsEncryptedException e) {
            askForPasswordAndRetry();
        }
    }

    private void askForPasswordAndRetry() {
        Objects.requireNonNull(rootController);
        Objects.requireNonNull(address);
        Objects.requireNonNull(amountEdit);
        OverlayableStackPaneController.OverlayUI<WalletPasswordController> pwd = rootController.overlayUI("wallet_password.fxml");
        final String addressStr = address.getText();
        final String amountStr = amountEdit.getText();
        pwd.controller.aesKeyProperty().addListener((observable, old, cur) -> {
            Objects.requireNonNull(rootController);
            // We only get here if the user found the right password. If they don't or they cancel, we end up back on
            // the main UI screen. By now the send money screen is history so we must recreate it.
            checkGuiThread();
            OverlayableStackPaneController.OverlayUI<SendMoneyController> screen = rootController.overlayUI("send_money.fxml");
            Objects.requireNonNull(screen.controller);
            Objects.requireNonNull(screen.controller.address);
            Objects.requireNonNull(screen.controller.amountEdit);
            screen.controller.aesKey = cur;
            screen.controller.address.setText(addressStr);
            screen.controller.amountEdit.setText(amountStr);
            screen.controller.send(null);
        });
    }

    private void updateTitleForBroadcast() {
        Objects.requireNonNull(sendResult);
        Objects.requireNonNull(titleLabel);
        final int peers = sendResult.transaction().getConfidence().numBroadcastPeers();
        titleLabel.setText(String.format("Broadcasting ... seen by %d peers", peers));
    }
}
