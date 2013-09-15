package wallettemplate.utils;

import javafx.scene.Scene;
import javafx.scene.control.TextField;

import java.util.function.Predicate;

public class TextFieldValidator {
    private boolean valid;

    public TextFieldValidator(TextField textField, Predicate<String> validator) {
        this.valid = validator.test(textField.getText());
        apply(textField, valid);
        textField.textProperty().addListener((observableValue, prev, current) -> {
            boolean nowValid = validator.test(current);
            if (nowValid == valid) return;
            apply(textField, nowValid);
            valid = nowValid;
        });
    }

    private static void apply(TextField textField, boolean nowValid) {
        if (nowValid) {
            textField.getStyleClass().remove("validation_error");
        } else {
            textField.getStyleClass().add("validation_error");
        }
    }

    public static void configureScene(Scene scene) {
        final String file = TextFieldValidator.class.getResource("text-validation.css").toString();
        scene.getStylesheets().add(file);
    }
}
