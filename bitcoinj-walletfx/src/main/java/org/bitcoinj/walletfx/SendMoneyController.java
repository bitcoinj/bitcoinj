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

import javafx.beans.value.ObservableValue;
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
import org.bitcoinj.walletfx.controls.BitcoinAddressValidator;
import org.bitcoinj.walletfx.utils.TextFieldValidator;
import org.bitcoinj.walletfx.utils.WTUtils;

import static com.google.common.base.Preconditions.checkState;
import org.bitcoinj.wallet.Wallet.MissingSigsMode;
import static org.bitcoinj.walletfx.utils.GuiUtils.*;

import javax.annotation.Nullable;
import javax.inject.Singleton;

@Singleton
public class SendMoneyController implements OverlayWindowController {
    @FXML private Button sendBtn;
    @FXML private Button cancelBtn;
    @FXML private Button signBtn;
    @FXML private TextField address;
    @FXML private Label titleLabel;
    @FXML private TextField amountEdit;
    @FXML private Label btcLabel;

    private OverlayableWindowController.OverlayUI overlayUI;

    private Wallet.SendResult sendResult;
    private KeyParameter aesKey;

    private final WalletFxApp app;
    private final WalletMainWindowController mainWindow;

    private HardwareSigner hwSigner;

    public SendMoneyController(WalletFxApp app, WalletMainWindowController mainWindow) {
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

    // Called by FXMLLoader
    public void initialize() {
        Coin balance = app.getWallet().getBalance();
        checkState(!balance.isZero());
        BitcoinAddressValidator addressValidator = new BitcoinAddressValidator(app.getNetParams(), address);
        addressValidator.getObservableValidity().addListener(this::addressValidityChanged);
        new TextFieldValidator(amountEdit, text ->
                !WTUtils.didThrow(() -> checkState(Coin.parseCoin(text).compareTo(balance) <= 0)));
        amountEdit.setText(balance.toPlainString());
        address.setPromptText(Address.fromKey(app.getNetParams(), new ECKey(), app.getPreferredOutputScriptType()).toString());
        initSigner();
    }

    public void setSigner(HardwareSigner hardwareSigner) {
        this.hwSigner = hardwareSigner;
        initSigner();
    }

    private void initSigner() {
        if (hwSigner != null) {
            signBtn.setText(hwSigner.getButtonText());
        }
    }

    private void addressValidityChanged(ObservableValue<? extends Boolean> observable, Boolean oldVal, Boolean newVal) {
        // Send is disabled if address is not valid or if wallet is watching wallet
        sendBtn.setDisable(!newVal || app.getWallet().isWatching());
        // Sign is disabled if address is not valid OR there is no hwSigner
        signBtn.setDisable(!newVal || hwSigner == null);
    }

    public void cancel(ActionEvent event) {
        overlayUI.done();
    }

    public void sign(ActionEvent event) {
        SendRequest req = createSendRequest();
        try {
            req.signInputs = false;
            req.missingSigsMode = MissingSigsMode.USE_OP_ZERO;
            // TODO: Make a configuration setting to enable/disable shuffleOutputs setting
            req.shuffleOutputs = false; // false for reproducible tests, true for privacy
            app.getWallet().completeTx(req);
        } catch (InsufficientMoneyException e) {
            informationalAlert("Could not empty the wallet",
                    "You may have too little money left in the wallet to make a transaction.");
            overlayUI.done();
        }
            hwSigner.displaySigningOverlay(req, this);
    }

    public void send(ActionEvent event) {
        // Address exception cannot happen as we validated it beforehand.
        try {
            SendRequest req = createSendRequest();
            sendResult = app.getWallet().sendCoins(req); // Sign and broadcast
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

    private SendRequest createSendRequest() {
        Coin amount = Coin.parseCoin(amountEdit.getText());
        Address destination = Address.fromString(app.getNetParams(), address.getText());
        SendRequest req;
        if (amount.equals(app.getWallet().getBalance()))
            req = SendRequest.emptyWallet(destination);
        else
            req = SendRequest.to(destination, amount);
        req.aesKey = aesKey;
        // Don't make the user wait for confirmations for now, as the intention is they're sending it
        // their own money!
        req.allowUnconfirmed();
        return req;
    }

    private void askForPasswordAndRetry() {
        OverlayableWindowController.OverlayUI<WalletPasswordController> pwd = mainWindow.overlayUI("wallet_password.fxml");
        final String addressStr = address.getText();
        final String amountStr = amountEdit.getText();
        pwd.controller.aesKeyProperty().addListener((observable, old, cur) -> {
            // We only get here if the user found the right password. If they don't or they cancel, we end up back on
            // the main UI screen. By now the send money screen is history so we must recreate it.
            checkGuiThread();
            OverlayableWindowController.OverlayUI<SendMoneyController> screen = mainWindow.overlayUI("send_money.fxml");
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
