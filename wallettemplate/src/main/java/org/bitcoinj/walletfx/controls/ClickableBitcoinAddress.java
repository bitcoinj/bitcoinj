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

package org.bitcoinj.walletfx.controls;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;

import javafx.beans.binding.StringExpression;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.ContextMenu;
import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
import javafx.scene.effect.DropShadow;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Pane;

import org.bitcoinj.core.Address;
import org.bitcoinj.uri.BitcoinURI;

import org.bitcoinj.walletfx.overlay.OverlayController;
import org.bitcoinj.walletfx.overlay.OverlayableStackPaneController;
import org.bitcoinj.walletfx.utils.GuiUtils;
import org.bitcoinj.walletfx.utils.QRCodeImages;

import de.jensd.fx.fontawesome.AwesomeDude;
import de.jensd.fx.fontawesome.AwesomeIcon;

import static javafx.beans.binding.Bindings.convert;

/**
 * A custom control that implements a clickable, copyable Bitcoin address. Clicking it opens a local wallet app. The
 * address looks like a blue hyperlink. Next to it there are two icons, one that copies to the clipboard and another
 * that shows a QRcode.
 */
public class ClickableBitcoinAddress extends AnchorPane implements OverlayController<ClickableBitcoinAddress> {
    @FXML protected Label addressLabel;
    @FXML protected ContextMenu addressMenu;
    @FXML protected Label copyWidget;
    @FXML protected Label qrCode;

    protected SimpleObjectProperty<Address> address = new SimpleObjectProperty<>();
    private final StringExpression addressStr;

    private OverlayableStackPaneController rootController;

    private String appName = "app-name";

    @Override
    public void initOverlay(OverlayableStackPaneController overlayableStackPaneController, OverlayableStackPaneController.OverlayUI<? extends OverlayController<ClickableBitcoinAddress>> ui) {
        rootController = overlayableStackPaneController;
    }

    /**
     * @param theAppName The application name to use in Bitcoin URIs
     */
    public void setAppName(String theAppName) {
        appName = theAppName;
    }



    public ClickableBitcoinAddress() {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("bitcoin_address.fxml"));
            loader.setRoot(this);
            loader.setController(this);
            // The following line is supposed to help Scene Builder, although it doesn't seem to be needed for me.
            loader.setClassLoader(getClass().getClassLoader());
            loader.load();

            AwesomeDude.setIcon(copyWidget, AwesomeIcon.COPY);
            Tooltip.install(copyWidget, new Tooltip("Copy address to clipboard"));

            AwesomeDude.setIcon(qrCode, AwesomeIcon.QRCODE);
            Tooltip.install(qrCode, new Tooltip("Show a barcode scannable with a mobile phone for this address"));

            addressStr = convert(address);
            addressLabel.textProperty().bind(addressStr);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String uri() {
        return BitcoinURI.convertToBitcoinURI(address.get(), null, appName, null);
    }

    public Address getAddress() {
        return address.get();
    }

    public void setAddress(Address address) {
        this.address.set(address);
    }

    public ObjectProperty<Address> addressProperty() {
        return address;
    }

    @FXML
    protected void copyAddress(ActionEvent event) {
        // User clicked icon or menu item.
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(addressStr.get());
        content.putHtml(String.format("<a href='%s'>%s</a>", uri(), addressStr.get()));
        clipboard.setContent(content);
    }

    @FXML
    protected void requestMoney(MouseEvent event) {
        if (event.getButton() == MouseButton.SECONDARY || (event.getButton() == MouseButton.PRIMARY && event.isMetaDown())) {
            // User right clicked or the Mac equivalent. Show the context menu.
            addressMenu.show(addressLabel, event.getScreenX(), event.getScreenY());
        } else {
            // User left clicked.
            try {
                Desktop.getDesktop().browse(URI.create(uri()));
            } catch (IOException e) {
                GuiUtils.informationalAlert("Opening wallet app failed", "Perhaps you don't have one installed?");
            }
        }
    }

    @FXML
    protected void copyWidgetClicked(MouseEvent event) {
        copyAddress(null);
    }

    @FXML
    protected void showQRCode(MouseEvent event) {
        Image qrImage = QRCodeImages.imageFromString(uri(), 320, 240);
        ImageView view = new ImageView(qrImage);
        view.setEffect(new DropShadow());
        // Embed the image in a pane to ensure the drop-shadow interacts with the fade nicely, otherwise it looks weird.
        // Then fix the width/height to stop it expanding to fill the parent, which would result in the image being
        // non-centered on the screen. Finally fade/blur it in.
        Pane pane = new Pane(view);
        pane.setMaxSize(qrImage.getWidth(), qrImage.getHeight());
        final OverlayableStackPaneController.OverlayUI<ClickableBitcoinAddress> overlay = rootController.overlayUI(pane, this);
        view.setOnMouseClicked(event1 -> overlay.done());
    }

}
