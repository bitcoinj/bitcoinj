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

import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.Service;
import com.google.protobuf.ByteString;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.Wallet;
import org.consensusj.supernautfx.FxmlLoaderFactory;
import org.consensusj.supernautfx.SupernautFxApp;
import org.bitcoinj.walletfx.utils.AppDataDirectory;
import org.bitcoinj.walletfx.utils.GuiUtils;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.time.Duration;

import static org.bitcoinj.walletfx.utils.GuiUtils.informationalAlert;

/**
 *  Interface for a Java FX Wallet Application
 */
public abstract class WalletFxApp implements SupernautFxApp {
    private final Script.ScriptType PREFERRED_OUTPUT_SCRIPT_TYPE = Script.ScriptType.P2WPKH;
    public static WalletFxApp instance;
    private final FxmlLoaderFactory loaderFactory;
    private final String mainFxmlResName;
    private final String mainCssResName;
    protected Stage primaryStage;
    protected WalletAppKit bitcoin;
    protected WalletMainWindowController mainWindowController;
    protected final NetworkParameters networkParameters;
    
    public WalletFxApp(FxmlLoaderFactory loaderFactory,
                       NetworkParameters networkParameters,
                       String mainFxmlResName,
                       String mainCssResName) {
        instance = this;
        this.loaderFactory = loaderFactory;
        this.networkParameters = networkParameters;
        this.mainFxmlResName = mainFxmlResName;
        this.mainCssResName = mainCssResName;
    }

    abstract public String getAppName();

    public NetworkParameters getNetParams() {
        return networkParameters;
    }

    public Script.ScriptType getPreferredOutputScriptType() {
        return PREFERRED_OUTPUT_SCRIPT_TYPE;
    }
    
    public String getWalletFileName() {
        return getAppName().replaceAll("[^a-zA-Z0-9.-]", "_") + "-"
                + networkParameters.getPaymentProtocolId();
    }

    public void start(Stage primaryStage) throws Exception {
        try {
            this.primaryStage = primaryStage;
            primaryStage.setTitle(getAppName());

            // Show the crash dialog for any exceptions that we don't handle and that hit the main loop.
            GuiUtils.handleCrashesOnThisThread();

            mainWindowController = startMainWindow(primaryStage, mainFxmlResName, mainCssResName);

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

            primaryStage.show();

            WalletSetPasswordController.estimateKeyDerivationTimeMsec();

            bitcoin.addListener(new Service.Listener() {
                @Override
                public void failed(Service.State from, Throwable failure) {
                    GuiUtils.crashAlert(failure);
                }
            }, Platform::runLater);
            bitcoin.startAsync();
        } catch (Throwable e) {
            GuiUtils.crashAlert(e);
            throw e;
        }
    }

    public void stop() throws Exception  {
        getWalletAppKit().stopAsync();
        getWalletAppKit().awaitTerminated();
    }

    public void setupWalletKit(@Nullable DeterministicSeed seed) {
        // If seed is non-null it means we are restoring from backup.
        File appDataDirectory = AppDataDirectory.get(getAppName()).toFile();
        bitcoin = new WalletAppKit(networkParameters, PREFERRED_OUTPUT_SCRIPT_TYPE, null, appDataDirectory, getWalletFileName()) {
            @Override
            protected void onSetupCompleted() {
                // Don't make the user wait for confirmations for now, as the intention is they're sending it
                // their own money!
                bitcoin.wallet().allowSpendingUnconfirmedTransactions();
                Platform.runLater(mainWindowController::onBitcoinSetup);
            }
        };
        // Now configure and start the appkit. This will take a second or two - we could show a temporary splash screen
        // or progress widget to keep the user engaged whilst we initialise, but we don't.
        if (networkParameters == RegTestParams.get()) {
            bitcoin.connectToLocalHost();   // You should run a regtest mode bitcoind locally.
        }
        bitcoin.setDownloadListener(mainWindowController.progressBarUpdater())
                .setBlockingStartup(false)
                .setUserAgent(getAppName(), "1.0");
        if (seed != null)
            bitcoin.restoreWalletFromSeed(seed);
    }

    public WalletMainWindowController startMainWindow(Stage primaryStage, String fxmlName, String cssName) throws IOException {
        // Load the GUI. The MainWindowController class will be automagically created and wired up.
        // Note that the location URL returned from getResource() will be in the package of the concrete subclass
        URL location = getClass().getResource(fxmlName);
        FXMLLoader loader = getFxmlLoaderFactory().get(location);
        Pane mainUI = loader.load();
        WalletMainWindowController mainWindowController = loader.getController();
        mainWindowController.mainUI = mainUI;

        Scene scene = mainWindowController.controllerStart(mainUI, cssName);
        primaryStage.setScene(scene);

        return mainWindowController;
    }

    public FxmlLoaderFactory getFxmlLoaderFactory() {
        return loaderFactory;
    }
    
    public WalletAppKit getWalletAppKit() {
        return bitcoin;
    }

    public Wallet getWallet() {
        return bitcoin.wallet();
    }

    static String TAG = WalletPasswordController.class.getName() + ".target-time";

    // Writes the given time to the wallet as a tag so we can find it again in this class.
    public void setTargetTime(Duration targetTime) {
        ByteString bytes = ByteString.copyFrom(Longs.toByteArray(targetTime.toMillis()));
        this.getWallet().setTag(TAG, bytes);
    }

    // Reads target time or throws if not set yet (should never happen).
    public Duration getTargetTime() throws IllegalArgumentException {
        return Duration.ofMillis(Longs.fromByteArray(this.getWallet().getTag(TAG).toByteArray()));
    }


}
