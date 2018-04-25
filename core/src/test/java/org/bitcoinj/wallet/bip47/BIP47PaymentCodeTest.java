/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.bip47.BIP47Account;
import org.bitcoinj.core.bip47.BIP47PaymentCode;
import org.bitcoinj.params.MainNetParams;
import org.junit.Test;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;

public class BIP47PaymentCodeTest {
    private final String ALICE_PAYMENT_CODE_V1 = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
    private final String ALICE_NOTIFICATION_ADDRESS = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
    private final String ALICE_NOTIFICATION_TESTADDRESS = "mxjb4tLKWrRsG3sGSMfgRPcFvCPkVgM4td";

    @Test
    public void pubKeyDeriveTests(){

        BIP47PaymentCode alice = new BIP47PaymentCode(ALICE_PAYMENT_CODE_V1);
        BIP47Account acc = new BIP47Account(MainNetParams.get(), ALICE_PAYMENT_CODE_V1);

        byte[] alice0th = alice.derivePubKeyAt(MainNetParams.get(),0);
        byte[] acc0th = acc.getNotificationKey().getPubKey();

        byte[] alice1st = alice.derivePubKeyAt(MainNetParams.get(),1);
        byte[] acc1st = acc.keyAt(1).getPubKey();

        assertEquals(HEX.encode(alice0th), HEX.encode(acc0th));
        assertEquals(HEX.encode(alice1st), HEX.encode(acc1st));
    }

    @Test(expected = AddressFormatException.class)
    public void invalidPaymentCodeTest1(){
        BIP47PaymentCode invalid = new BIP47PaymentCode("XXXTJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA");
    }

    @Test(expected = AddressFormatException.class)
    public void invalidPaymentCodeTest2(){
        BIP47PaymentCode invalid = new BIP47PaymentCode("");
    }

    @Test(expected = AddressFormatException.class)
    public void invalidPaymentCodeTest3(){
        new BIP47PaymentCode(ALICE_PAYMENT_CODE_V1.replace('x','y'));
    }
}