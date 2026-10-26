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

import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.walletfx.overlay.OverlayableStackPaneController;

/**
 * Abstract controller class for a wallet application's main window (i.e. the one that is the primary @{code Stage})
 */
public abstract class MainWindowController extends OverlayableStackPaneController {
    protected Scene scene;

    public Scene scene() {
        return scene;
    }

    public abstract void controllerStart(Pane mainUI, String cssResourceName);

    public abstract void onBitcoinSetup();

    public abstract void restoreFromSeedAnimation();

    public abstract DownloadProgressTracker progressBarUpdater();
}
