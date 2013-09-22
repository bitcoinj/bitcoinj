package wallettemplate;

import com.aquafx_project.AquaFx;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.kits.WalletAppKit;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.params.RegTestParams;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.bitcoin.utils.Threading;
import com.google.common.base.Throwables;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import wallettemplate.utils.GuiUtils;
import wallettemplate.utils.TextFieldValidator;

import java.io.File;
import java.io.IOException;
import java.net.URL;

public class Main extends Application {
    public static String APP_NAME = "WalletTemplate";

    public static NetworkParameters params = MainNetParams.get();
    public static WalletAppKit bitcoin;
    public static Main instance;

    private StackPane uiStack;
    private Pane mainUI;

    @Override
    public void start(Stage mainWindow) throws Exception {
        instance = this;
        GuiUtils.handleCrashesOnThisThread();
        try {
            init(mainWindow);
        } catch (Throwable t) {
            // Nicer message for the case where the block store file is locked.
            if (Throwables.getRootCause(t) instanceof BlockStoreException) {
                GuiUtils.informationalAlert("Already running", "This application is already running and cannot be started twice.");
            } else {
                throw t;
            }
        }
    }

    private void init(Stage mainWindow) throws IOException {
        if (System.getProperty("os.name").toLowerCase().contains("mac")) {
            AquaFx.style();
        }
        // Load the GUI. The Controller class will be automagically created and wired up.
        URL location = getClass().getResource("main.fxml");
        FXMLLoader loader = new FXMLLoader(location);
        mainUI = (Pane) loader.load();
        Controller controller = loader.getController();
        // Configure the window with a StackPane so we can overlay things on top of the main UI.
        uiStack = new StackPane(mainUI);
        mainWindow.setTitle(APP_NAME);
        final Scene scene = new Scene(uiStack);
        TextFieldValidator.configureScene(scene);   // Add CSS that we need.
        mainWindow.setScene(scene);

        // Make log output concise.
        BriefLogFormatter.init();
        // Tell bitcoinj to run event handlers on the JavaFX UI thread. This keeps things simple and means
        // we cannot forget to switch threads when adding event handlers. Unfortunately, the DownloadListener
        // we give to the app kit is currently an exception and runs on a library thread. It'll get fixed in
        // a future version.
        Threading.USER_THREAD = Platform::runLater;
        // Create the app kit. It won't do any heavyweight initialization until after we start it.
        bitcoin = new WalletAppKit(params, new File("."), APP_NAME);
        if (params == RegTestParams.get()) {
            bitcoin.connectToLocalHost();   // You should run a regtest mode bitcoind locally.
        } else if (params == MainNetParams.get()) {
            // Checkpoints are block headers that ship inside our app: for a new user, we pick the last header
            // in the checkpoints file and then download the rest from the network. It makes things much faster.
            // Checkpoint files are made using the BuildCheckpoints tool and usually we have to download the
            // last months worth or more (takes a few seconds).
            bitcoin.setCheckpoints(getClass().getResourceAsStream("checkpoints"));
        }

        // Now configure and start the appkit. This will take a second or two - we could show a temporary splash screen
        // or progress widget to keep the user engaged whilst we initialise, but we don't.
        bitcoin.setDownloadListener(controller.progressBarUpdater())
               .setBlockingStartup(false)
               .startAndWait();
        // Don't make the user wait for confirmations for now, as the intention is they're sending it their own money!
        bitcoin.wallet().allowSpendingUnconfirmedTransactions();
        System.out.println(bitcoin.wallet());
        controller.onBitcoinSetup();
        mainWindow.show();
    }

    public class OverlayUI {
        Node ui;
        Object controller;

        public OverlayUI(Node ui, Object controller) {
            this.ui = ui;
            this.controller = controller;
        }

        public void done() {
            GuiUtils.fadeOutAndRemove(ui, uiStack);
            GuiUtils.blurIn(mainUI);
            this.ui = null;
            this.controller = null;
        }
    }

    /** Loads the FXML file with the given name, blurs out the main UI and puts this one on top. */
    public OverlayUI overlayUI(String name) {
        try {
            // Load the UI from disk.
            URL location = getClass().getResource(name);
            FXMLLoader loader = new FXMLLoader(location);
            Pane ui = (Pane) loader.load();
            Object controller = loader.getController();
            OverlayUI pair = new OverlayUI(ui, controller);
            // Auto-magically set the overlayUi member, if it's there.
            try {
                controller.getClass().getDeclaredField("overlayUi").set(controller, pair);
            } catch (IllegalAccessException | NoSuchFieldException ignored) {
            }
            GuiUtils.blurOut(mainUI);
            uiStack.getChildren().add(ui);
            GuiUtils.fadeIn(ui);
            return pair;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }

    @Override
    public void stop() throws Exception {
        bitcoin.stopAndWait();
        super.stop();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
