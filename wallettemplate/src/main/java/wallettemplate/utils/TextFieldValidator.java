package wallettemplate.utils;

import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.scene.Scene;
import javafx.scene.control.TextInputControl;

import java.util.function.Predicate;

public class TextFieldValidator {
    public final BooleanProperty valid = new SimpleBooleanProperty(false);

    public TextFieldValidator(TextInputControl control, Predicate<String> validator) {
        this.valid.set(validator.test(control.getText()));
        apply(control, valid.get());
        control.textProperty().addListener((observableValue, prev, current) -> {
            boolean nowValid = validator.test(current);
            if (nowValid == valid.get()) return;
            valid.set(nowValid);
        });
        valid.addListener(o -> apply(control, valid.get()));
    }

    private static void apply(TextInputControl textField, boolean nowValid) {
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
