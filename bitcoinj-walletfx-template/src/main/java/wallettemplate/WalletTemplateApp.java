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

import javafx.stage.Stage;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.walletfx.WalletFxApp;
import org.consensusj.supernautfx.FxmlLoaderFactory;
import org.consensusj.supernautfx.SupernautFxLauncher;

import javax.inject.Singleton;

/**
 * Main class for WalletTemplate that uses SupernautFx and does not have
 * to subclass javafx.application.Application.
 */
@Singleton
public class WalletTemplateApp extends WalletFxApp {
    private static final String APP_NAME = "WalletTemplate";
    private static final String APP_DATA_DIR_NAME = "bitcoinj";
    private static final String WALLET_FILE_BASE_NAME = APP_DATA_DIR_NAME;
    private static final String mainFxmlResName = "main.fxml";
    private static final String mainCssResName = "wallet.css";

    public static void main(String[] args) {
        SupernautFxLauncher.superLaunch(WalletTemplateApp.class, args);
    }

    WalletTemplateApp(FxmlLoaderFactory loaderFactory) {
        super(loaderFactory,
                TestNet3Params.get(),
                Script.ScriptType.P2WPKH,
                KeyChainGroupStructure.DEFAULT,
                mainFxmlResName,
                mainCssResName);
    }

    @Override
    public String getAppName() {
        return WalletTemplateApp.APP_NAME;
    }

    @Override
    protected String getAppDataDirName() {
        return APP_DATA_DIR_NAME;
    }

    @Override
    protected String getWalletFileBaseName() {
        return WALLET_FILE_BASE_NAME;
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
