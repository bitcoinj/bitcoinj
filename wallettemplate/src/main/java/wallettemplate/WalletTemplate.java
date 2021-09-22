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

import javafx.fxml.FXMLLoader;
import javafx.scene.layout.Pane;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.script.Script;
import org.bitcoinj.walletfx.application.WalletApplication;

import java.io.IOException;
import java.net.URL;

/**
 * Template implementation of WalletApplication
 */
public class WalletTemplate extends WalletApplication {

    public WalletTemplate(String applicationName, NetworkParameters params, Script.ScriptType preferredOutputScriptType) {
        super(applicationName, params, preferredOutputScriptType);
    }

    @Override
    protected MainController loadController() throws IOException {
        // Load the GUI. The MainController class will be automagically created and wired up.
        URL location = getClass().getResource("main.fxml");
        FXMLLoader loader = new FXMLLoader(location);
        Pane mainUI = loader.load();
        MainController controller = loader.getController();

        controller.controllerStart(mainUI, "wallet.css");
        return controller;
    }
}
