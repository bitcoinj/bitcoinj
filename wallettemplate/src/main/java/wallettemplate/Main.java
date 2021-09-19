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

import com.google.common.util.concurrent.*;
import javafx.scene.input.*;
import org.bitcoinj.utils.AppDataDirectory;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.DeterministicSeed;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import org.bitcoinj.walletfx.utils.GuiUtils;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.net.URL;

import static org.bitcoinj.walletfx.utils.GuiUtils.informationalAlert;

public class Main extends Application {
    public static NetworkParameters params = TestNet3Params.get();
    public static final Script.ScriptType PREFERRED_OUTPUT_SCRIPT_TYPE = Script.ScriptType.P2WPKH;
    public static final String APP_NAME = "WalletTemplate";
    private static final String WALLET_FILE_NAME = APP_NAME.replaceAll("[^a-zA-Z0-9.-]", "_") + "-"
            + params.getPaymentProtocolId();

    public static WalletAppKit bitcoin;
    public static Main instance;

    public MainController controller;

    @Override
    public void start(Stage mainWindow) throws Exception {
        try {
            realStart(mainWindow);
        } catch (Throwable e) {
            GuiUtils.crashAlert(e);
            throw e;
        }
    }

    private void realStart(Stage mainWindow) throws IOException {
        instance = this;
        // Show the crash dialog for any exceptions that we don't handle and that hit the main loop.
        GuiUtils.handleCrashesOnThisThread();

        if (Utils.isMac()) {
            // We could match the Mac Aqua style here, except that (a) Modena doesn't look that bad, and (b)
            // the date picker widget is kinda broken in AquaFx and I can't be bothered fixing it.
            // AquaFx.style();
        }

        // Load the GUI. The MainController class will be automagically created and wired up.
        URL location = getClass().getResource("main.fxml");
        FXMLLoader loader = new FXMLLoader(location);
        Pane mainUI = loader.load();
        controller = loader.getController();

        Scene scene = controller.controllerStart(mainUI, "wallet.css");
        mainWindow.setScene(scene);

        // Make log output concise.
        BriefLogFormatter.init();
        // Tell bitcoinj to run event handlers on the JavaFX UI thread. This keeps things simple and means
        // we cannot forget to switch threads when adding event handlers. Unfortunately, the DownloadListener
        // we give to the app kit is currently an exception and runs on a library thread. It'll get fixed in
        // a future version.
        Threading.USER_THREAD = Platform::runLater;
        // Create the app kit. It won't do any heavyweight initialization until after we start it.
        setupWalletKit(null);

        if (bitcoin.isChainFileLocked()) {
            informationalAlert("Already running", "This application is already running and cannot be started twice.");
            Platform.exit();
            return;
        }

        mainWindow.show();

        WalletSetPasswordController.estimateKeyDerivationTimeMsec();

        bitcoin.addListener(new Service.Listener() {
            @Override
            public void failed(Service.State from, Throwable failure) {
                GuiUtils.crashAlert(failure);
            }
        }, Platform::runLater);
        bitcoin.startAsync();

        scene.getAccelerators().put(KeyCombination.valueOf("Shortcut+F"), () -> bitcoin.peerGroup().getDownloadPeer().close());
    }

    public void setupWalletKit(@Nullable DeterministicSeed seed) {
        // If seed is non-null it means we are restoring from backup.
        File appDataDirectory = AppDataDirectory.get(APP_NAME).toFile();
        bitcoin = new WalletAppKit(params, PREFERRED_OUTPUT_SCRIPT_TYPE, null, appDataDirectory, WALLET_FILE_NAME) {
            @Override
            protected void onSetupCompleted() {
                Platform.runLater(controller::onBitcoinSetup);
            }
        };
        // Now configure and start the appkit. This will take a second or two - we could show a temporary splash screen
        // or progress widget to keep the user engaged whilst we initialise, but we don't.
        if (params == RegTestParams.get()) {
            bitcoin.connectToLocalHost();   // You should run a regtest mode bitcoind locally.
        }
        bitcoin.setDownloadListener(controller.progressBarUpdater())
               .setBlockingStartup(false)
               .setUserAgent(APP_NAME, "1.0");
        if (seed != null)
            bitcoin.restoreWalletFromSeed(seed);
    }


    @Override
    public void stop() throws Exception {
        bitcoin.stopAsync();
        bitcoin.awaitTerminated();
        // Forcibly terminate the JVM because Orchid likes to spew non-daemon threads everywhere.
        Runtime.getRuntime().exit(0);
    }

    public static void main(String[] args) {
        launch(args);
    }
}
