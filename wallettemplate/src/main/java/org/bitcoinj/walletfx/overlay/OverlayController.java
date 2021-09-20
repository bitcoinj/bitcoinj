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

/**
 * Interface for controllers displayed via OverlayWindow.OverlayUI
 */
public interface OverlayController<T> {
    /**
     * @param rootController The root controller (containing the StackPane)
     * @param ui The overlay UI (node, controller pair)
     */
    void initOverlay(OverlayableStackPaneController rootController, OverlayableStackPaneController.OverlayUI<? extends OverlayController<T>> ui);
}
