package wallettemplate;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.Wallet;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import wallettemplate.utils.GuiUtils;

public class SendMoneyController {
    public Button sendBtn;
    public Button cancelBtn;
    public TextField address;
    public Label titleLabel;

    public Main.OverlayUI overlayUi;

    // Called by FXMLLoader
    public void initialize() {
        new BitcoinAddressValidator(Main.params, address, sendBtn);
    }

    public void cancel(ActionEvent event) {
        overlayUi.done();
    }

    public void send(ActionEvent event) {
        try {
            Address destination = new Address(Main.params, address.getText());
            Wallet.SendRequest req = Wallet.SendRequest.emptyWallet(destination);
            final Wallet.SendResult sendResult = Main.bitcoin.wallet().sendCoins(req);
            if (sendResult == null) {
                // We couldn't empty the wallet for some reason. TODO: When bitcoinj issue 425 is fixed, be more helpful
                GuiUtils.informationalAlert("Could not empty the wallet",
                        "You may have too little money left in the wallet to make a transaction.");
                overlayUi.done();
                return;
            }
            Futures.addCallback(sendResult.broadcastComplete, new FutureCallback<Transaction>() {
                @Override
                public void onSuccess(Transaction result) {
                    // TODO: Fix bitcoinj so these callbacks run on the user thread.
                    Platform.runLater(overlayUi::done);
                }

                @Override
                public void onFailure(Throwable t) {
                    // We died trying to empty the wallet.
                    GuiUtils.crashAlert(t);
                }
            });
            sendBtn.setDisable(true);
            address.setDisable(true);
            titleLabel.setText("Broadcasting ...");
        } catch (AddressFormatException e) {
            // Cannot happen because we already validated it when the text field changed.
            throw new RuntimeException(e);
        }
    }
}
