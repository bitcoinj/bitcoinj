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

import com.google.common.util.concurrent.Service;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.input.KeyCombination;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.Wallet;
import org.consensusj.supernautfx.FxmlLoaderFactory;
import org.consensusj.supernautfx.SupernautFxApp;
import org.consensusj.supernautfx.SupernautFxLauncher;
import wallettemplate.controls.NotificationBarPane;
import wallettemplate.utils.AppDataDirectory;
import wallettemplate.utils.GuiUtils;
import wallettemplate.utils.TextFieldValidator;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.io.File;
import java.io.IOException;
import java.net.URL;

import static wallettemplate.utils.GuiUtils.informationalAlert;

/**
 * Main class for WalletTemplate that uses SupernautFx and does not have
 * to subclass javafx.application.Application. This is basically copied from the old
 * Main class which is now deprecated.
 */
@Singleton
public class WalletTemplateApp extends WalletFxApp   {
    @Deprecated
    public static final String APP_NAME = "WalletTemplate";

    public static void main(String[] args) {
        SupernautFxLauncher.superLaunch(WalletTemplateApp.class, args);
    }

    WalletTemplateApp(WalletTemplateMainWindow mainWindow) {
        super(mainWindow, TestNet3Params.get());
    }

    @Override
    public String getAppName() {
        return WalletTemplateApp.APP_NAME;
    }

    @Override
    public void init() throws Exception {
        super.init();
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        super.start(primaryStage);
    }

    @Override
    public void stop() throws Exception {
        super.stop();
        // Forcibly terminate the JVM because Orchid likes to spew non-daemon threads everywhere.
        Runtime.getRuntime().exit(0);
    }
}
