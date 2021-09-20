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
package org.bitcoinj.walletfx.overlay;

import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import org.bitcoinj.walletfx.utils.GuiUtils;

import javax.annotation.Nullable;

import java.io.IOException;
import java.net.URL;

import static org.bitcoinj.walletfx.utils.GuiUtils.blurIn;
import static org.bitcoinj.walletfx.utils.GuiUtils.blurOut;
import static org.bitcoinj.walletfx.utils.GuiUtils.checkGuiThread;
import static org.bitcoinj.walletfx.utils.GuiUtils.explodeOut;
import static org.bitcoinj.walletfx.utils.GuiUtils.fadeIn;
import static org.bitcoinj.walletfx.utils.GuiUtils.fadeOutAndRemove;
import static org.bitcoinj.walletfx.utils.GuiUtils.zoomIn;

/**
 * Abstract Controller for a {@link StackPane} that can have other {@link Pane}s displayed on top of it as a modals.
 */
public abstract class OverlayableStackPaneController {
    /**
     * The {@link StackPane} that contains the {@code mainUI} and any active overlays. Typically, this
     * will be the root node of a {@code Scene} contained in a {@code Stage}.
     */
    protected final StackPane uiStack = new StackPane();
    /**
     * The {@link Pane} containing the bottom-most view, that can be overlaid with other views.
     */
    protected Pane mainUI;
    private final Node stopClickPane = new Pane();
    @Nullable
    private OverlayUI<? extends OverlayController<?>> currentOverlay;


    public <T extends OverlayController<T>> OverlayUI<T> overlayUI(Node node, T controller) {
        checkGuiThread();
        OverlayUI<T> pair = new OverlayUI<>(node, controller);
        controller.initOverlay(this, pair);
        pair.show();
        return pair;
    }

    /** Loads the FXML file with the given name, blurs out the main UI and puts this one on top. */
    public <T extends OverlayController<T>> OverlayUI<T> overlayUI(String name) {
        try {
            checkGuiThread();
            // Load the UI from disk.
            URL location = GuiUtils.getResource(this.getClass(), name);
            FXMLLoader loader = new FXMLLoader(location);
            Pane overlayNode = loader.load();
            T controller = loader.getController();
            OverlayUI<T> pair = new OverlayUI<>(overlayNode, controller);
            controller.initOverlay(this, pair);
            pair.show();
            return pair;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }

    public class OverlayUI<T extends OverlayController<T>> {
        private Node ui;
        public T controller;

        public OverlayUI(Node ui, T controller) {
            this.ui = ui;
            this.controller = controller;
        }

        public void show() {
            checkGuiThread();
            if (currentOverlay == null) {
                uiStack.getChildren().add(stopClickPane);
                uiStack.getChildren().add(ui);
                blurOut(mainUI);
                //darken(mainUI);
                fadeIn(ui);
                zoomIn(ui);
            } else {
                // Do a quick transition between the current overlay and the next.
                // Bug here: we don't pay attention to changes in outsideClickDismisses.
                explodeOut(currentOverlay.ui);
                fadeOutAndRemove(uiStack, currentOverlay.ui);
                uiStack.getChildren().add(ui);
                ui.setOpacity(0.0);
                fadeIn(ui, 100);
                zoomIn(ui, 100);
            }
            currentOverlay = this;
        }

        public void outsideClickDismisses() {
            stopClickPane.setOnMouseClicked((ev) -> done());
        }

        public void done() {
            checkGuiThread();
            if (ui == null) return;  // In the middle of being dismissed and got an extra click.
            explodeOut(ui);
            fadeOutAndRemove(uiStack, ui, stopClickPane);
            blurIn(mainUI);
            //undark(mainUI);
            this.ui = null;
            this.controller = null;
            currentOverlay = null;
        }
    }
}
