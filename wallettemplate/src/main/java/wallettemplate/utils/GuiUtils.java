package wallettemplate.utils;

import com.google.common.base.Throwables;
import javafx.animation.*;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.effect.GaussianBlur;
import javafx.scene.layout.Pane;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.IOException;
import java.util.function.BiConsumer;

import static com.google.common.base.Preconditions.checkState;

public class GuiUtils {
    public static void runAlert(BiConsumer<Stage, AlertWindowController> setup) {
        try {
            // JavaFX2 doesn't actually have a standard alert template. Instead the Scene Builder app will create FXML
            // files for an alert window for you, and then you customise it as you see fit. I guess it makes sense in
            // an odd sort of way.
            Stage dialogStage = new Stage();
            dialogStage.initModality(Modality.APPLICATION_MODAL);
            FXMLLoader loader = new FXMLLoader(GuiUtils.class.getResource("alert.fxml"));
            Pane pane = loader.load();
            AlertWindowController controller = loader.getController();
            setup.accept(dialogStage, controller);
            dialogStage.setScene(new Scene(pane));
            dialogStage.showAndWait();
        } catch (IOException e) {
            // We crashed whilst trying to show the alert dialog (this should never happen). Give up!
            throw new RuntimeException(e);
        }
    }

    public static void crashAlert(Throwable t) {
        t.printStackTrace();
        Throwable rootCause = Throwables.getRootCause(t);
        Runnable r = () -> {
            runAlert((stage, controller) -> controller.crashAlert(stage, rootCause.toString()));
            Platform.exit();
        };
        if (Platform.isFxApplicationThread())
            r.run();
        else
            Platform.runLater(r);
    }

    /** Show a GUI alert box for any unhandled exceptions that propagate out of this thread. */
    public static void handleCrashesOnThisThread() {
        Thread.currentThread().setUncaughtExceptionHandler((thread, exception) -> {
            GuiUtils.crashAlert(Throwables.getRootCause(exception));
        });
    }

    public static void informationalAlert(String message, String details, Object... args) {
        String formattedDetails = String.format(details, args);
        Runnable r = () -> runAlert((stage, controller) -> controller.informational(stage, message, formattedDetails));
        if (Platform.isFxApplicationThread())
            r.run();
        else
            Platform.runLater(r);
    }

    private static final int UI_ANIMATION_TIME_MSEC = 350;

    public static void fadeIn(Node ui) {
        FadeTransition ft = new FadeTransition(Duration.millis(UI_ANIMATION_TIME_MSEC), ui);
        ft.setFromValue(0.0);
        ft.setToValue(1.0);
        ft.play();
    }

    public static Animation fadeOut(Node ui) {
        FadeTransition ft = new FadeTransition(Duration.millis(UI_ANIMATION_TIME_MSEC), ui);
        ft.setFromValue(ui.getOpacity());
        ft.setToValue(0.0);
        ft.play();
        return ft;
    }

    public static Animation fadeOutAndRemove(Node ui, Pane parentPane) {
        Animation animation = fadeOut(ui);
        animation.setOnFinished(actionEvent -> parentPane.getChildren().remove(ui));
        return animation;
    }

    public static void blurOut(Node node) {
        GaussianBlur blur = new GaussianBlur(0.0);
        node.setEffect(blur);
        Timeline timeline = new Timeline();
        KeyValue kv = new KeyValue(blur.radiusProperty(), 10.0);
        KeyFrame kf = new KeyFrame(Duration.millis(UI_ANIMATION_TIME_MSEC), kv);
        timeline.getKeyFrames().add(kf);
        timeline.play();
    }

    public static void blurIn(Node node) {
        GaussianBlur blur = (GaussianBlur) node.getEffect();
        Timeline timeline = new Timeline();
        KeyValue kv = new KeyValue(blur.radiusProperty(), 0.0);
        KeyFrame kf = new KeyFrame(Duration.millis(UI_ANIMATION_TIME_MSEC), kv);
        timeline.getKeyFrames().add(kf);
        timeline.setOnFinished(actionEvent -> node.setEffect(null));
        timeline.play();
    }

    public static void checkGuiThread() {
        checkState(Platform.isFxApplicationThread());
    }
}
