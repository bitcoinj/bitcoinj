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

package org.bitcoinj.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.List;

import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.wallet.AllowUnconfirmedCoinSelector;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.junit.Test;

import com.google.common.collect.Lists;

public class TransactionInputTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();

    @Test
    public void testStandardWalletDisconnect() throws Exception {
        Wallet w = new Wallet(new Context(UNITTEST));
        w.setCoinSelector(new AllowUnconfirmedCoinSelector());
        Address a = w.currentReceiveAddress();
        Transaction tx1 = FakeTxBuilder.createFakeTxWithoutChangeAddress(UNITTEST, Coin.COIN, a);
        w.receivePending(tx1, null);
        Transaction tx2 = new Transaction(UNITTEST);
        tx2.addOutput(Coin.valueOf(99000000), new ECKey());
        w.completeTx(SendRequest.forTx(tx2));

        TransactionInput txInToDisconnect = tx2.getInput(0);

        assertEquals(tx1, txInToDisconnect.getOutpoint().fromTx);
        assertNull(txInToDisconnect.getOutpoint().connectedOutput);

        txInToDisconnect.disconnect();

        assertNull(txInToDisconnect.getOutpoint().fromTx);
        assertNull(txInToDisconnect.getOutpoint().connectedOutput);
    }

    @Test
    public void testUTXOWalletDisconnect() throws Exception {
        Wallet w = new Wallet(new Context(UNITTEST));
        Address a = w.currentReceiveAddress();
        final UTXO utxo = new UTXO(Sha256Hash.of(new byte[] { 1, 2, 3 }), 1, Coin.COIN, 0, false,
                ScriptBuilder.createOutputScript(a));
        w.setUTXOProvider(new UTXOProvider() {
            @Override
            public NetworkParameters getParams() {
                return UNITTEST;
            }

            @Override
            public List<UTXO> getOpenTransactionOutputs(List<ECKey> addresses) throws UTXOProviderException {
                return Lists.newArrayList(utxo);
            }

            @Override
            public int getChainHeadHeight() throws UTXOProviderException {
                return Integer.MAX_VALUE;
            }
        });

        Transaction tx2 = new Transaction(UNITTEST);
        tx2.addOutput(Coin.valueOf(99000000), new ECKey());
        w.completeTx(SendRequest.forTx(tx2));

        TransactionInput txInToDisconnect = tx2.getInput(0);

        assertNull(txInToDisconnect.getOutpoint().fromTx);
        assertEquals(utxo.getHash(), txInToDisconnect.getOutpoint().connectedOutput.getParentTransactionHash());

        txInToDisconnect.disconnect();

        assertNull(txInToDisconnect.getOutpoint().fromTx);
        assertNull(txInToDisconnect.getOutpoint().connectedOutput);
    }
}
