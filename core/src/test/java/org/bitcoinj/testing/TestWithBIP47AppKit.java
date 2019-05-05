
/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.testing;

import org.bitcoinj.kits.BIP47AppKit;

public class TestWithBIP47AppKit extends TestWithWallet {
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    public void setWallet(BIP47AppKit w){
        this.wallet = w.getvWallet();
    }
}
