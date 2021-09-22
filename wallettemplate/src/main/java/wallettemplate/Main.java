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

import javafx.application.Application;
import javafx.stage.Stage;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.walletfx.application.AppDelegate;

/**
 * Proxy JavaFX {@link Application} that delegates all functionality
 * to {@link WalletTemplate}
 */
public class Main extends Application {
    private static final NetworkParameters params = TestNet3Params.get();
    private static final Script.ScriptType PREFERRED_OUTPUT_SCRIPT_TYPE = Script.ScriptType.P2WPKH;
    private static final String APP_NAME = "WalletTemplate";

    private final AppDelegate delegate;

    public static void main(String[] args) {
        launch(args);
    }

    public Main() {
        delegate = new WalletTemplate(APP_NAME, params, PREFERRED_OUTPUT_SCRIPT_TYPE);
    }

    @Override
    public void init() throws Exception {
        delegate.init(this);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        delegate.start(primaryStage);
    }

    @Override
    public void stop() throws Exception {
        delegate.stop();
    }
}
