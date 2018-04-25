/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;

public class NotSecp256k1Exception extends Exception {
    public NotSecp256k1Exception() {
    }

    public NotSecp256k1Exception(String message) {
        super(message);
    }

    public NotSecp256k1Exception(String message, Throwable cause) {
        super(message, cause);
    }

    public NotSecp256k1Exception(Throwable cause) {
        super(cause);
    }
}
