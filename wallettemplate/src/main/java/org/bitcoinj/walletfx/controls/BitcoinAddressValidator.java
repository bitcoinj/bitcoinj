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

import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.NetworkParameters;

import javafx.scene.Node;
import javafx.scene.control.TextField;
import org.bitcoinj.walletfx.utils.TextFieldValidator;

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
        field.textProperty().addListener((observableValue, prev, current) -> toggleButtons(current));
        toggleButtons(field.getText());
    }

    private void toggleButtons(String current) {
        boolean valid = testAddr(current);
        for (Node n : nodes) n.setDisable(!valid);
    }

    private boolean testAddr(String text) {
        try {
            Address.fromString(params, text);
            return true;
        } catch (AddressFormatException e) {
            return false;
        }
    }
}
