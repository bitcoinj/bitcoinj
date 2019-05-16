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

import javafx.animation.FadeTransition;
import javafx.animation.ParallelTransition;
import javafx.animation.TranslateTransition;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.util.Duration;
import org.bitcoinj.core.Coin;
import org.bitcoinj.walletfx.OverlayableWindowController;
import org.bitcoinj.walletfx.WalletFxApp;
import org.bitcoinj.walletfx.WalletMainWindowController;
import org.bitcoinj.walletfx.WalletSettingsController;
import org.bitcoinj.walletfx.controls.ClickableBitcoinAddress;
import org.bitcoinj.walletfx.controls.NotificationBarPane;
import org.bitcoinj.walletfx.utils.easing.EasingMode;
import org.bitcoinj.walletfx.utils.easing.ElasticInterpolator;

import javax.inject.Singleton;

/**
 * Subclass of WalletMainWindowController that allows customization
 */
@Singleton
public class WalletTemplateMainWindowController extends WalletMainWindowController {
    @FXML private HBox controlsBox;
    @FXML private Label balance;
    @FXML private Button sendMoneyOutBtn;
    @FXML private ClickableBitcoinAddress addressControl;

    public WalletTemplateMainWindowController(WalletFxApp app) {
        super(app);
    }

    // Called by FXMLLoader.
    public void initialize() {
        addressControl.setOpacity(0.0);
    }


    public void onBitcoinSetup() {
        super.onBitcoinSetup();
        addressControl.addressProperty().bind(model.addressProperty());
        balance.textProperty().bind(createBalanceStringBinding(model.balanceProperty()));
        // Don't let the user click send money when the wallet is empty.
        sendMoneyOutBtn.disableProperty().bind(model.balanceProperty().isEqualTo(Coin.ZERO));

    }


    @FXML
    private void sendMoneyOut(ActionEvent event) {
        // Hide this UI and show the send money UI. This UI won't be clickable until the user dismisses send_money.
        overlayUI("send_money.fxml");
    }

    @FXML
    private void settingsClicked(ActionEvent event) {
        OverlayableWindowController.OverlayUI<WalletSettingsController> screen = overlayUI("wallet_settings.fxml");
        screen.controller.initialize(null);
    }

    @Override
    public void restoreFromSeedAnimation() {
        // Buttons slide out ...
        TranslateTransition leave = new TranslateTransition(Duration.millis(1200), controlsBox);
        leave.setByY(80.0);
        leave.play();
    }

    @Override
    protected void readyToGoAnimation() {
        // Buttons slide in and clickable address appears simultaneously.
        TranslateTransition arrive = new TranslateTransition(Duration.millis(1200), controlsBox);
        arrive.setInterpolator(new ElasticInterpolator(EasingMode.EASE_OUT, 1, 2));
        arrive.setToY(0.0);
        FadeTransition reveal = new FadeTransition(Duration.millis(1200), addressControl);
        reveal.setToValue(1.0);
        ParallelTransition group = new ParallelTransition(arrive, reveal);
        group.setDelay(NotificationBarPane.ANIM_OUT_DURATION);
        group.setCycleCount(1);
        group.play();
    }
}
