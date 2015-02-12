package wallettemplate;

import org.bitcoinj.crypto.KeyCrypterScrypt;
import javafx.event.ActionEvent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.image.ImageView;
import javafx.scene.layout.GridPane;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;
import wallettemplate.utils.KeyDerivationTasks;

import java.time.Duration;

import static wallettemplate.utils.GuiUtils.*;

public class WalletSetPasswordController {
    private static final Logger log = LoggerFactory.getLogger(WalletSetPasswordController.class);
    public PasswordField pass1, pass2;

    public ImageView padlockImage;
    public ProgressIndicator progressMeter;
    public GridPane widgetGrid;
    public Button closeButton;
    public Label explanationLabel;

    public Main.OverlayUI overlayUI;

    public void initialize() {
        padlockImage.setOpacity(0);
        progressMeter.setOpacity(0);
    }

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
        fadeIn(padlockImage);
        fadeOut(widgetGrid);
        fadeOut(explanationLabel);
        fadeOut(closeButton);

        // Figure out how fast this computer can scrypt. We do it on the UI thread because the delay should be small
        // and so we don't really care about blocking here.
        IdealPasswordParameters params = new IdealPasswordParameters(password);
        KeyCrypterScrypt scrypt = new KeyCrypterScrypt(params.realIterations);
        // Write the target time to the wallet so we can make the progress bar work when entering the password.
        WalletPasswordController.setTargetTime(params.realTargetTime);

        // Deriving the actual key runs on a background thread.
        KeyDerivationTasks tasks = new KeyDerivationTasks(scrypt, password, params.realTargetTime) {
            @Override
            protected void onFinish(KeyParameter aesKey) {
                // The actual encryption part doesn't take very long as most private keys are derived on demand.
                Main.bitcoin.wallet().encrypt(scrypt, aesKey);
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

    private static class IdealPasswordParameters {
        public final int realIterations;
        public final Duration realTargetTime;

        public IdealPasswordParameters(String password) {
            final int targetTimeMsec = 2000;

            int iterations = 16384;
            KeyCrypterScrypt scrypt = new KeyCrypterScrypt(iterations);
            long now = System.currentTimeMillis();
            scrypt.deriveKey(password);
            long time = System.currentTimeMillis() - now;
            log.info("Initial iterations took {} msec", time);

            // N can only be a power of two, so we keep shifting both iterations and doubling time taken
            // until we are in sorta the right general area.
            while (time < targetTimeMsec) {
                iterations <<= 1;
                time *= 2;
            }

            realIterations = iterations;
            // Fudge it by +10% to ensure our progress meter is always a bit behind the real encryption. Plus
            // without this it seems the real scrypting always takes a bit longer than we estimated for some reason.
            realTargetTime = Duration.ofMillis((long) (time * 1.1));
        }
    }
}
