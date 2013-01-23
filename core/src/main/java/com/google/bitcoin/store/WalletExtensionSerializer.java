/*
 * Copyright 2012 Google Inc.
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

package com.google.bitcoin.store;

import java.util.Collection;
import java.util.Collections;

import org.bitcoinj.wallet.Protos;

import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.crypto.KeyCrypter;

/**
 * Optional helper for WalletProtobufSerializer that allows for serialization and deserialization of Wallet objects
 * with extensions and corresponding extended Wallet classes. If you want to store proprietary data into the wallet,
 * this is how to do it.
 */
public class WalletExtensionSerializer {
    public Wallet newWallet(NetworkParameters params) {
        return new Wallet(params);
    }

    public Wallet newWallet(NetworkParameters params, KeyCrypter keyCrypter) {
        return new Wallet(params, keyCrypter);
    }

    public void readExtension(Wallet wallet, Protos.Extension extProto) {
        if (extProto.getMandatory()) {
            throw new IllegalArgumentException("Unknown mandatory extension in the wallet: " + extProto.getId());
        }
    }

    /**
     * Get collection of extensions to add, should be overridden by any class adding wallet extensions.
     */
    public Collection<Protos.Extension> getExtensionsToWrite(Wallet wallet) {
        return Collections.emptyList();
    }
}
