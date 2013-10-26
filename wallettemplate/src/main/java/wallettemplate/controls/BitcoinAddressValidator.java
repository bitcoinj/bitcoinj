package wallettemplate.controls;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.NetworkParameters;
import javafx.scene.Node;
import javafx.scene.control.TextField;
import wallettemplate.utils.TextFieldValidator;

/**
 * Given a text field, some network params and optionally some nodes, will make the text field an angry red colour
 * if the address is invalid for those params, and enable/disable the nodes.
 */
public class BitcoinAddressValidator {
    private NetworkParameters params;
    private Node[] nodes;

    public BitcoinAddressValidator(NetworkParameters params, TextField field, Node... nodes) {
        this.params = params;
        this.nodes = nodes;

        // Handle the red highlighting, but don't highlight in red just when the field is empty because that makes
        // the example/prompt address hard to read.
        new TextFieldValidator(field, text -> text.isEmpty() || testAddr(text));
        // However we do want the buttons to be disabled when empty so we apply a different test there.
        field.textProperty().addListener((observableValue, prev, current) -> {
            toggleButtons(current);
        });
        toggleButtons(field.getText());
    }

    private void toggleButtons(String current) {
        boolean valid = testAddr(current);
        for (Node n : nodes) n.setDisable(!valid);
    }

    private boolean testAddr(String text) {
        try {
            new Address(params, text);
            return true;
        } catch (AddressFormatException e) {
            return false;
        }
    }
}
