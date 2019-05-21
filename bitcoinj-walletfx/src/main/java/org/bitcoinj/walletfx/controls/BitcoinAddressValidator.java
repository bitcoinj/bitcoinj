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

import javafx.beans.binding.Bindings;
import javafx.beans.binding.BooleanBinding;
import javafx.beans.value.ObservableBooleanValue;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.NetworkParameters;

import javafx.scene.control.TextField;
import org.bitcoinj.walletfx.utils.TextFieldValidator;

/**
 * Given a text field, some network params, will make the text field an angry red colour
 * if the address is invalid for those params. {@code getObservableValidity() can be used
 * to enable/disable buttons, etc that depend on a valid address}
 */
public class BitcoinAddressValidator {
    private final BooleanBinding valid;
    private NetworkParameters params;
    private TextFieldValidator textFieldValidator;

    public BitcoinAddressValidator(NetworkParameters params, final TextField field) {
        this.params = params;

        // Handle the red highlighting, but don't highlight in red just when the field is empty because that makes
        // the example/prompt address hard to read.
        textFieldValidator = new TextFieldValidator(field, text -> text.isEmpty() || testAddr(text));

        // However we do want buttons, etc to be disabled when empty so the valid binding is invalid when empty.
        valid = Bindings.createBooleanBinding(
                                () -> testAddr(field.textProperty().get()),
                                field.textProperty());
    }

    /**
     * Get an observable boolean for address validity.
     * @return A boolean observable
     */
    public ObservableBooleanValue getObservableValidity() {
        return valid;
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
