package wallettemplate;

import com.google.bitcoin.core.*;
import com.google.bitcoin.uri.BitcoinURI;
import javafx.animation.*;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.scene.control.Button;
import javafx.scene.control.*;
import javafx.scene.control.Label;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.util.Duration;
import wallettemplate.utils.GuiUtils;

import java.awt.*;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.util.Date;

import static com.google.common.base.Preconditions.checkState;
import static javafx.application.Platform.isFxApplicationThread;
import static wallettemplate.Main.bitcoin;

/**
 * Gets created auto-magically by FXMLLoader via reflection. The widget fields are set to the GUI controls they're named
 * after. This class handles all the updates and event handling for the main UI.
 */
public class Controller {
    public ProgressBar syncProgress;
    public VBox syncBox;
    public HBox controlsBox;
    public Label requestMoneyLink;
    public Label balance;
    public ContextMenu addressMenu;
    public HBox addressLabelBox;
    public Button sendMoneyOutBtn;
    public ImageView copyWidget;

    private Address primaryAddress;

    // Called by FXMLLoader.
    public void initialize() {
        syncProgress.setProgress(-1);
        addressLabelBox.setOpacity(0.0);
        Tooltip tooltip = new Tooltip("Copy address to clipboard");
        Tooltip.install(copyWidget, tooltip);
    }

    public void onBitcoinSetup() {
        bitcoin.wallet().addEventListener(new BalanceUpdater());
        primaryAddress = bitcoin.wallet().getKeys().get(0).toAddress(Main.params);
        refreshBalanceLabel();
    }

    public void requestMoney(MouseEvent event) {
        // User clicked on the address.
        if (event.getButton() == MouseButton.SECONDARY || (event.getButton() == MouseButton.PRIMARY && event.isMetaDown())) {
            addressMenu.show(requestMoneyLink, event.getScreenX(), event.getScreenY());
        } else {
            String uri = getURI();
            System.out.println("Opening " + uri);
            try {
                Desktop.getDesktop().browse(URI.create(uri));
            } catch (IOException e) {
                // Couldn't open wallet app.
                GuiUtils.informationalAlert("Opening wallet app failed", "Perhaps you don't have one installed?");
            }
        }
    }

    private String getURI() {
        return BitcoinURI.convertToBitcoinURI(getAddress(), Utils.COIN, Main.APP_NAME, null);
    }

    private String getAddress() {
        return primaryAddress.toString();
    }

    public void copyWidgetClicked(MouseEvent event) {
        copyAddress(null);
    }

    public void copyAddress(ActionEvent event) {
        // User clicked icon or menu item.
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(getAddress());
        content.putHtml(String.format("<a href='%s'>%s</a>", getURI(), getAddress()));
        clipboard.setContent(content);
    }

    public void sendMoneyOut(ActionEvent event) {
        // Hide this UI and show the send money UI. This UI won't be clickable until the user dismisses send_money.
        Main.instance.overlayUI("send_money.fxml");
    }

    public class ProgressBarUpdater extends DownloadListener {
        @Override
        protected void progress(double pct, int blocksSoFar, Date date) {
            super.progress(pct, blocksSoFar, date);
            Platform.runLater(() -> syncProgress.setProgress(pct / 100.0));
        }

        @Override
        protected void doneDownload() {
            super.doneDownload();
            Platform.runLater(Controller.this::readyToGoAnimation);
        }
    }

    public void readyToGoAnimation() {
        // Sync progress bar slides out ...
        TranslateTransition leave = new TranslateTransition(Duration.millis(600), syncBox);
        leave.setByY(80.0);
        // Buttons slide in and clickable address appears simultaneously.
        TranslateTransition arrive = new TranslateTransition(Duration.millis(600), controlsBox);
        arrive.setToY(0.0);
        requestMoneyLink.setText(primaryAddress.toString());
        FadeTransition reveal = new FadeTransition(Duration.millis(500), addressLabelBox);
        reveal.setToValue(1.0);
        ParallelTransition group = new ParallelTransition(arrive, reveal);
        // Slide out happens then slide in/fade happens.
        SequentialTransition both = new SequentialTransition(leave, group);
        both.setCycleCount(1);
        both.setInterpolator(Interpolator.EASE_BOTH);
        both.play();
    }

    public ProgressBarUpdater progressBarUpdater() {
        return new ProgressBarUpdater();
    }

    public class BalanceUpdater extends AbstractWalletEventListener {
        @Override
        public void onWalletChanged(Wallet wallet) {
            checkState(isFxApplicationThread());
            refreshBalanceLabel();
        }
    }

    public void refreshBalanceLabel() {
        final BigInteger amount = bitcoin.wallet().getBalance(Wallet.BalanceType.ESTIMATED);
        balance.setText(Utils.bitcoinValueToFriendlyString(amount));
    }
}
