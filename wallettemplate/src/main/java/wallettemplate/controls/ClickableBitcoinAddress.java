package wallettemplate.controls;

import com.google.bitcoin.uri.BitcoinURI;
import de.jensd.fx.fontawesome.AwesomeDude;
import de.jensd.fx.fontawesome.AwesomeIcon;
import javafx.beans.property.StringProperty;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
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
import net.glxn.qrgen.QRCode;
import net.glxn.qrgen.image.ImageType;
import wallettemplate.Main;
import wallettemplate.utils.GuiUtils;

import java.awt.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;

// This control can be used with Scene Builder as long as we don't use any Java 8 features yet. Once Oracle release
// a new Scene Builder compiled against Java 8, we'll be able to use lambdas and so on here. Until that day comes,
// this file specifically must be recompiled against Java 7 for main.fxml to be editable visually.
//
// From the java directory:
//
// javac -cp $HOME/.m2/repository/net/glxn/qrgen/1.3/qrgen-1.3.jar:$HOME/.m2/repository/de/jensd/fontawesomefx/8.0.0/fontawesomefx-8.0.0.jar:../../../target/classes:../../../../core/target/bitcoinj-0.11-SNAPSHOT.jar -d ../../../target/classes/ -source 1.7 -target 1.7 wallettemplate/controls/ClickableBitcoinAddress.java


/**
 * A custom control that implements a clickable, copyable Bitcoin address. Clicking it opens a local wallet app. The
 * address looks like a blue hyperlink. Next to it there are two icons, one that copies to the clipboard and another
 * that shows a QRcode.
 */
public class ClickableBitcoinAddress extends AnchorPane {
    @FXML protected Label addressLabel;
    @FXML protected ContextMenu addressMenu;
    @FXML protected Label copyWidget;
    @FXML protected Label qrCode;

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
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String uri() {
        return BitcoinURI.convertToBitcoinURI(getAddress(), null, Main.APP_NAME, null);
    }

    public String getAddress() {
        return addressLabel.getText();
    }

    public void setAddress(String address) {
        addressLabel.setText(address);
    }

    public StringProperty addressProperty() {
        return addressLabel.textProperty();
    }

    @FXML
    protected void copyAddress(ActionEvent event) {
        // User clicked icon or menu item.
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(getAddress());
        content.putHtml(String.format("<a href='%s'>%s</a>", uri(), getAddress()));
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
        // Serialize to PNG and back into an image. Pretty lame but it's the shortest code to write and I'm feeling
        // lazy tonight.
        final byte[] imageBytes = QRCode
                .from(uri())
                .withSize(320, 240)
                .to(ImageType.PNG)
                .stream()
                .toByteArray();
        Image qrImage = new Image(new ByteArrayInputStream(imageBytes));
        ImageView view = new ImageView(qrImage);
        view.setEffect(new DropShadow());
        // Embed the image in a pane to ensure the drop-shadow interacts with the fade nicely, otherwise it looks weird.
        // Then fix the width/height to stop it expanding to fill the parent, which would result in the image being
        // non-centered on the screen. Finally fade/blur it in.
        Pane pane = new Pane(view);
        pane.setMaxSize(qrImage.getWidth(), qrImage.getHeight());
        final Main.OverlayUI<ClickableBitcoinAddress> overlay = Main.instance.overlayUI(pane, this);
        view.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                overlay.done();
            }
        });
    }
}
