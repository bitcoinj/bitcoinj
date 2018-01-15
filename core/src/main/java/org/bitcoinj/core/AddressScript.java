/*
 * Copyright 2018 John Jegutanis
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
package org.bitcoinj.core;

import org.bitcoinj.script.Script.ScriptType;

public interface AddressScript {
    enum AddressFormat {
        BASE58,
        BECH32
    }

    /** Get the script type of this address */
    ScriptType getScriptType();

    /** Get the hash value of this address */
    byte[] getValue();

    /** Get the network parameters of this address */
    NetworkParameters getParameters();

    /** Get the destination type */
    AddressFormat getAddressFormat();
}
