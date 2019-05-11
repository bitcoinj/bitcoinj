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

import javafx.fxml.FXML;
import javafx.scene.layout.HBox;
import org.bitcoinj.core.*;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.MoreExecutors;

import javafx.event.ActionEvent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import org.bouncycastle.crypto.params.KeyParameter;
import wallettemplate.controls.BitcoinAddressValidator;
import wallettemplate.utils.TextFieldValidator;
import wallettemplate.utils.WTUtils;

import static com.google.common.base.Preconditions.checkState;
import static wallettemplate.utils.GuiUtils.*;

import javax.annotation.Nullable;
import javax.inject.Singleton;

@Singleton
public class SendMoneyController implements OverlayWindowController {
    @FXML private Button sendBtn;
    @FXML private Button cancelBtn;
    @FXML private TextField address;
    @FXML private Label titleLabel;
    @FXML private TextField amountEdit;
    @FXML private Label btcLabel;

    private OverlayableWindow.OverlayUI overlayUI;

    private Wallet.SendResult sendResult;
    private KeyParameter aesKey;

    private final WalletFxApp app;
    private final WalletMainWindow mainWindow;

    public SendMoneyController(WalletFxApp app, WalletMainWindow mainWindow) {
        this.app = app;
        this.mainWindow = mainWindow;
    }

    @Override
    public OverlayableWindow.OverlayUI getOverlayUI() {
        return overlayUI;
    }

    @Override
    public void setOverlayUI(OverlayableWindow.OverlayUI ui) {
        overlayUI = ui;
    }

    // Called by FXMLLoader
    public void initialize() {
        Coin balance = app.getWallet().getBalance();
        checkState(!balance.isZero());
        new BitcoinAddressValidator(app.getNetParams(), address, sendBtn);
        new TextFieldValidator(amountEdit, text ->
                !WTUtils.didThrow(() -> checkState(Coin.parseCoin(text).compareTo(balance) <= 0)));
        amountEdit.setText(balance.toPlainString());
        address.setPromptText(Address.fromKey(app.getNetParams(), new ECKey(), app.getPreferredOutputScriptType()).toString());
    }

    public void cancel(ActionEvent event) {
        overlayUI.done();
    }

    public void send(ActionEvent event) {
        // Address exception cannot happen as we validated it beforehand.
        try {
            Coin amount = Coin.parseCoin(amountEdit.getText());
            Address destination = Address.fromString(app.getNetParams(), address.getText());
            SendRequest req;
            if (amount.equals(app.getWallet().getBalance()))
                req = SendRequest.emptyWallet(destination);
            else
                req = SendRequest.to(destination, amount);
            req.aesKey = aesKey;
            sendResult = app.getWallet().sendCoins(req);
            Futures.addCallback(sendResult.broadcastComplete, new FutureCallback<Transaction>() {
                @Override
                public void onSuccess(@Nullable Transaction result) {
                    checkGuiThread();
                    overlayUI.done();
                }

                @Override
                public void onFailure(Throwable t) {
                    // We died trying to empty the wallet.
                    crashAlert(t);
                }
            }, MoreExecutors.directExecutor());
            sendResult.tx.getConfidence().addEventListener((tx, reason) -> {
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
        OverlayableWindow.OverlayUI<WalletPasswordController> pwd = mainWindow.overlayUI("wallet_password.fxml");
        final String addressStr = address.getText();
        final String amountStr = amountEdit.getText();
        pwd.controller.aesKeyProperty().addListener((observable, old, cur) -> {
            // We only get here if the user found the right password. If they don't or they cancel, we end up back on
            // the main UI screen. By now the send money screen is history so we must recreate it.
            checkGuiThread();
            OverlayableWindow.OverlayUI<SendMoneyController> screen = mainWindow.overlayUI("send_money.fxml");
            screen.controller.aesKey = cur;
            screen.controller.address.setText(addressStr);
            screen.controller.amountEdit.setText(amountStr);
            screen.controller.send(null);
        });
    }

    private void updateTitleForBroadcast() {
        final int peers = sendResult.tx.getConfidence().numBroadcastPeers();
        titleLabel.setText(String.format("Broadcasting ... seen by %d peers", peers));
    }
}
