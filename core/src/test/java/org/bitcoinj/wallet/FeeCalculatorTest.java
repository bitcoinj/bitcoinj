/*
 * Copyright 2015 jrn.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.wallet;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Wallet;
import org.bitcoinj.params.MainNetParams;

import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class FeeCalculatorTest {
    private NetworkParameters params;

    @Before
    public void setUp() throws Exception {
        params = MainNetParams.get();
        Context context = new Context(params);
    }

    @Test
    public void shouldCalculateSendRequestFee() {
        ECKey key = new ECKey();
        Address address = key.toAddress(params);
        Transaction previousTx = new Transaction(params);
        TransactionOutput previousOut = previousTx.addOutput(Coin.COIN, address);

        Wallet.SendRequest req = Wallet.SendRequest.to(address, Coin.COIN);
        req.fee = Coin.ZERO;
        req.feePerKb = Coin.CENT;
        FeeCalculator feeCalculator = new DefaultFeeCalculator();
        Coin expected = Coin.CENT;
        Coin actual = feeCalculator.calculateFees(req, req.tx.getOptimalEncodingMessageSize());
        assertEquals(expected, actual);
    }

    @Test
    public void shouldCalculateTransactionFee() {
        ECKey key = new ECKey();
        Address address = key.toAddress(params);
        Transaction previousTx = new Transaction(params);
        TransactionOutput previousOut = previousTx.addOutput(Coin.COIN, address);
        Transaction tx = new Transaction(params);

        tx.addInput(previousOut);
        tx.addOutput(Coin.COIN, address);

        FeeCalculator feeCalculator = new DefaultFeeCalculator();
        Coin expected = Coin.CENT;
        Coin actual = feeCalculator.calculateFees(Coin.ZERO, Coin.CENT, tx);
        assertEquals(expected, actual);
    }
}
