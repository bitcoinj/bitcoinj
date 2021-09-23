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

package org.bitcoinj.walletfx.application;

import com.google.common.util.concurrent.Service;
import javafx.application.Platform;
import javafx.scene.input.KeyCombination;
import javafx.stage.Stage;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.AppDataDirectory;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.walletfx.utils.GuiUtils;
import wallettemplate.WalletSetPasswordController;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;

import static org.bitcoinj.walletfx.utils.GuiUtils.informationalAlert;

/**
 * Base class for JavaFX Wallet Applications
 */
public abstract class WalletApplication implements AppDelegate {
    private static WalletApplication instance;
    private WalletAppKit walletAppKit;
    private final String applicationName;
    private final NetworkParameters params;
    private final Script.ScriptType preferredOutputScriptType;
    private final String walletFileName;
    private MainWindowController controller;

    public WalletApplication(String applicationName, NetworkParameters params, Script.ScriptType preferredOutputScriptType) {
        instance = this;
        this.applicationName = applicationName;
        this.walletFileName = applicationName.replaceAll("[^a-zA-Z0-9.-]", "_") + "-" + params.getPaymentProtocolId();
        this.params = params;
        this.preferredOutputScriptType = preferredOutputScriptType;
    }

    public static WalletApplication instance() {
        return instance;
    }

    public WalletAppKit walletAppKit() {
        return walletAppKit;
    }

    public String applicationName() {
        return applicationName;
    }

    public NetworkParameters params() {
        return params;
    }

    public Script.ScriptType preferredOutputScriptType() {
        return preferredOutputScriptType;
    }

    public MainWindowController mainWindowController() {
        return controller;
    }

    protected abstract MainWindowController loadController() throws IOException;

    @Override
    public void start(Stage primaryStage) throws Exception {
        try {
            startImpl(primaryStage);
        } catch (Throwable e) {
            GuiUtils.crashAlert(e);
            throw e;
        }
    }

    private void startImpl(Stage primaryStage) throws IOException {
        // Show the crash dialog for any exceptions that we don't handle and that hit the main loop.
        GuiUtils.handleCrashesOnThisThread();

        // Make log output concise.
        BriefLogFormatter.init();

        if (Utils.isMac()) {
            // We could match the Mac Aqua style here, except that (a) Modena doesn't look that bad, and (b)
            // the date picker widget is kinda broken in AquaFx and I can't be bothered fixing it.
            // AquaFx.style();
        }
        controller = loadController();
        primaryStage.setScene(controller.scene());
        startWalletAppKit(primaryStage);
        controller.scene().getAccelerators().put(KeyCombination.valueOf("Shortcut+F"), () -> walletAppKit().peerGroup().getDownloadPeer().close());
    }

    protected void startWalletAppKit(Stage primaryStage) throws IOException {
        // Tell bitcoinj to run event handlers on the JavaFX UI thread. This keeps things simple and means
        // we cannot forget to switch threads when adding event handlers. Unfortunately, the DownloadListener
        // we give to the app kit is currently an exception and runs on a library thread. It'll get fixed in
        // a future version.
        Threading.USER_THREAD = Platform::runLater;
        // Create the app kit. It won't do any heavyweight initialization until after we start it.
        setupWalletKit(null);

        if (walletAppKit.isChainFileLocked()) {
            informationalAlert("Already running", "This application is already running and cannot be started twice.");
            Platform.exit();
            return;
        }

        primaryStage.show();

        WalletSetPasswordController.initEstimatedKeyDerivationTime();

        walletAppKit.addListener(new Service.Listener() {
            @Override
            public void failed(Service.State from, Throwable failure) {
                GuiUtils.crashAlert(failure);
            }
        }, Platform::runLater);
        walletAppKit.startAsync();
    }

    public void setupWalletKit(@Nullable DeterministicSeed seed) {
        // If seed is non-null it means we are restoring from backup.
        File appDataDirectory = AppDataDirectory.get(applicationName).toFile();
        walletAppKit = new WalletAppKit(params, preferredOutputScriptType, null, appDataDirectory, walletFileName) {
            @Override
            protected void onSetupCompleted() {
                Platform.runLater(controller::onBitcoinSetup);
            }
        };
        // Now configure and start the appkit. This will take a second or two - we could show a temporary splash screen
        // or progress widget to keep the user engaged whilst we initialise, but we don't.
        if (params == RegTestParams.get()) {
            walletAppKit.connectToLocalHost();   // You should run a regtest mode bitcoind locally.
        }
        walletAppKit.setDownloadListener(controller.progressBarUpdater())
                .setBlockingStartup(false)
                .setUserAgent(applicationName, "1.0");
        if (seed != null)
            walletAppKit.restoreWalletFromSeed(seed);
    }

    @Override
    public void stop() throws Exception {
        walletAppKit.stopAsync();
        walletAppKit.awaitTerminated();
        // Forcibly terminate the JVM because Orchid likes to spew non-daemon threads everywhere.
        Runtime.getRuntime().exit(0);
    }
}
