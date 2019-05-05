
/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.crypto.bip47;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.bip47.BIP47Account;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

public class BIP47AccountTest {
    private static final Logger log = LoggerFactory.getLogger(BIP47AccountTest.class);

    private final String ALICE_PAYMENT_CODE_V1 = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
    private final String ALICE_NOTIFICATION_ADDRESS = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
    private final String ALICE_NOTIFICATION_TESTADDRESS = "mxjb4tLKWrRsG3sGSMfgRPcFvCPkVgM4td";

    @Test
    public void constructFromPaymentCode() throws Exception {
        // a valid payment code
        BIP47Account acc = new BIP47Account(MainNetParams.get(), ALICE_PAYMENT_CODE_V1);
        assertEquals(acc.getStringPaymentCode(), ALICE_PAYMENT_CODE_V1);
        assertEquals(ALICE_NOTIFICATION_ADDRESS, acc.getNotificationAddress().toString());


        BIP47Account testAcc = new BIP47Account(TestNet3Params.get(), ALICE_PAYMENT_CODE_V1);
        assertEquals(testAcc.getStringPaymentCode(), ALICE_PAYMENT_CODE_V1);
        assertEquals(ALICE_NOTIFICATION_TESTADDRESS, testAcc.getNotificationAddress().toString());

        // invalid payment code
        try {
            BIP47Account badAcc = new BIP47Account(MainNetParams.get(), ALICE_PAYMENT_CODE_V1.substring(0, 10));
        } catch (AddressFormatException expected){
            assertTrue(expected.getMessage().equalsIgnoreCase("Checksum does not validate"));
        }
    }
}