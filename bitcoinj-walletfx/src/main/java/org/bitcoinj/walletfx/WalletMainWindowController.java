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

import javafx.beans.binding.Binding;
import javafx.beans.binding.Bindings;
import javafx.beans.value.ObservableValue;
import javafx.scene.Scene;
import javafx.scene.input.KeyCombination;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.utils.MonetaryFormat;
import org.bitcoinj.walletfx.utils.BitcoinUIModel;
import app.supernaut.fx.FxmlLoaderFactory;
import org.bitcoinj.walletfx.controls.NotificationBarPane;
import org.bitcoinj.walletfx.utils.TextFieldValidator;

/**
 * Combine OverlayableWindow with WalletApp
 */
public abstract class WalletMainWindowController extends OverlayableWindowController {
    public static WalletMainWindowController instance;
    protected final WalletFxApp app;
    public NotificationBarPane notificationBar;
    protected WalletAppKit bitcoin;
    protected BitcoinUIModel model = new BitcoinUIModel();
    private NotificationBarPane.Item syncItem;
    private static final MonetaryFormat MONETARY_FORMAT = MonetaryFormat.BTC.noCode();


    public WalletMainWindowController(WalletFxApp app) {
        WalletMainWindowController.instance = this;
        this.app = app;
    }
    
    public void onBitcoinSetup() {
        model.setWallet(app.getWallet());

        showBitcoinSyncMessage();
        model.syncProgressProperty().addListener(x -> {
            if (model.syncProgressProperty().get() >= 1.0) {
                readyToGoAnimation();
                if (syncItem != null) {
                    syncItem.cancel();
                    syncItem = null;
                }
            } else if (syncItem == null) {
                showBitcoinSyncMessage();
            }
        });
    }

    public static String formatCoin(Coin coin) {
        return MONETARY_FORMAT.format(coin).toString();
    }

    public static Binding<String> createBalanceStringBinding(ObservableValue<Coin> coinProperty) {
        return Bindings.createStringBinding(() -> formatCoin(coinProperty.getValue()), coinProperty);
    }

    private void showBitcoinSyncMessage() {
        syncItem = notificationBar.pushItem("Synchronising with the Bitcoin network", model.syncProgressProperty());
    }

    public abstract void restoreFromSeedAnimation();
    protected abstract void readyToGoAnimation();
    
    public DownloadProgressTracker progressBarUpdater() {
        return model.getDownloadProgressTracker();
    }


    Scene controllerStart(Pane mainUI, String cssResourceName) {
        // Configure the window with a StackPane so we can overlay things on top of the main UI, and a
        // NotificationBarPane so we can slide messages and progress bars in from the bottom. Note that
        // ordering of the construction and connection matters here, otherwise we get (harmless) CSS error
        // spew to the logs.
        notificationBar = new NotificationBarPane(mainUI);
        uiStack = new StackPane();
        Scene scene = new Scene(uiStack);
        TextFieldValidator.configureScene(scene);
        // Add CSS that we need. wallet.css will be loaded from the same package
        // as the implementing subclass of WalletMainWindow.
        scene.getStylesheets().add(getClass().getResource(cssResourceName).toString());
        uiStack.getChildren().add(notificationBar);
        scene.getAccelerators().put(KeyCombination.valueOf("Shortcut+F"), () -> bitcoin.peerGroup().getDownloadPeer().close());
        return scene;
    }

    @Override
    FxmlLoaderFactory getFxmlLoaderFactory() {
        return app.getFxmlLoaderFactory();
    }
}
