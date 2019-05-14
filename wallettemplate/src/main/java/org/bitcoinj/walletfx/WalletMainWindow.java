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

import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.input.KeyCombination;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import org.bitcoinj.core.Utils;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.consensusj.supernautfx.FxmlLoaderFactory;
import org.bitcoinj.walletfx.controls.NotificationBarPane;
import org.bitcoinj.walletfx.utils.GuiUtils;
import org.bitcoinj.walletfx.utils.TextFieldValidator;
import wallettemplate.WalletTemplateApp;

import java.io.IOException;
import java.net.URL;

/**
 * Combine OverlayableWindow with WalletApp
 */
public abstract class WalletMainWindow extends OverlayableWindow {
    public static WalletMainWindow instance;
    protected final FxmlLoaderFactory loaderFactory;
    public NotificationBarPane notificationBar;
    public Stage primaryStage;
    protected WalletAppKit bitcoin;
    protected MainController controller;

    public WalletMainWindow(FxmlLoaderFactory loaderFactory) {
        WalletMainWindow.instance = this;
        this.loaderFactory = loaderFactory;
    }

    public void restoreFromSeedAnimation() {
        controller.restoreFromSeedAnimation();;
    }

    void realStart(Stage primaryStage) throws IOException {
        this.primaryStage = primaryStage;
        // Show the crash dialog for any exceptions that we don't handle and that hit the main loop.
        GuiUtils.handleCrashesOnThisThread();

        if (Utils.isMac()) {
            // We could match the Mac Aqua style here, except that (a) Modena doesn't look that bad, and (b)
            // the date picker widget is kinda broken in AquaFx and I can't be bothered fixing it.
            // AquaFx.style();
        }

        // Load the GUI. The MainController class will be automagically created and wired up.
        // Note that the location URL returned from getResource() will be in the package of the concrete subclass
        URL location = getClass().getResource("main.fxml");
        FXMLLoader loader = loaderFactory.get(location);
        mainUI = loader.load();
        controller = loader.getController();
        // Configure the window with a StackPane so we can overlay things on top of the main UI, and a
        // NotificationBarPane so we can slide messages and progress bars in from the bottom. Note that
        // ordering of the construction and connection matters here, otherwise we get (harmless) CSS error
        // spew to the logs.
        notificationBar = new NotificationBarPane(mainUI);
        primaryStage.setTitle(WalletTemplateApp.APP_NAME);
        uiStack = new StackPane();
        Scene scene = new Scene(uiStack);
        TextFieldValidator.configureScene(scene);
        // Add CSS that we need. wallet.css will be loaded from the same package
        // as the implementing subclass of WalletMainWindow.
        scene.getStylesheets().add(getClass().getResource("wallet.css").toString());
        uiStack.getChildren().add(notificationBar);
        primaryStage.setScene(scene);

        // Make log output concise.
        BriefLogFormatter.init();
        // Tell bitcoinj to run event handlers on the JavaFX UI thread. This keeps things simple and means
        // we cannot forget to switch threads when adding event handlers. Unfortunately, the DownloadListener
        // we give to the app kit is currently an exception and runs on a library thread. It'll get fixed in
        // a future version.
        Threading.USER_THREAD = Platform::runLater;
        // Create the app kit. It won't do any heavyweight initialization until after we start it.

        scene.getAccelerators().put(KeyCombination.valueOf("Shortcut+F"), () -> bitcoin.peerGroup().getDownloadPeer().close());
    }


    @Override
    FxmlLoaderFactory getFxmlLoaderFactory() {
        return loaderFactory;
    }
}
