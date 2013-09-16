package wallettemplate.utils;

import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.stage.Stage;

public class AlertWindowController {
    public Label messageLabel;
    public Label detailsLabel;
    public Button okButton;
    public Button cancelButton;
    public Button actionButton;

    /** Initialize this alert dialog for information about a crash. */
    public void crashAlert(Stage stage, String crashMessage) {
        messageLabel.setText("Unfortunately, we screwed up and the app crashed. Sorry about that!");
        detailsLabel.setText(crashMessage);

        cancelButton.setVisible(false);
        actionButton.setVisible(false);
        okButton.setOnAction(actionEvent -> stage.close());
    }

    /** Initialize this alert for general information: OK button only, nothing happens on dismissal. */
    public void informational(Stage stage, String message, String details) {
        messageLabel.setText(message);
        detailsLabel.setText(details);
        cancelButton.setVisible(false);
        actionButton.setVisible(false);
        okButton.setOnAction(actionEvent -> stage.close());
    }
}
