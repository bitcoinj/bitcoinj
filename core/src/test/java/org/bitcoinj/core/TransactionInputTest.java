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

import com.google.common.collect.Lists;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitParamsRunner.class)
public class TransactionInputTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();

    @Before
    public void setUp() throws Exception {
        Context.propagate(new Context());
    }

    @Test
    public void testStandardWalletDisconnect() throws Exception {
        Wallet w = Wallet.createDeterministic(BitcoinNetwork.TESTNET, ScriptType.P2PKH);
        Address a = w.currentReceiveAddress();
        Transaction tx1 = FakeTxBuilder.createFakeTxWithoutChangeAddress(Coin.COIN, a);
        w.receivePending(tx1, null);
        Transaction tx2 = new Transaction();
        tx2.addOutput(Coin.valueOf(99000000), new ECKey());
        SendRequest req = SendRequest.forTx(tx2);
        req.allowUnconfirmed();
        w.completeTx(req);

        TransactionInput txInToDisconnect = tx2.getInput(0);

        assertEquals(tx1, txInToDisconnect.getOutpoint().fromTx);
        assertNull(txInToDisconnect.getOutpoint().connectedOutput);

        txInToDisconnect.disconnect();

        assertNull(txInToDisconnect.getOutpoint().fromTx);
        assertNull(txInToDisconnect.getOutpoint().connectedOutput);
    }

    @Test
    public void testUTXOWalletDisconnect() throws Exception {
        Wallet w = Wallet.createDeterministic(BitcoinNetwork.TESTNET, ScriptType.P2PKH);
        Address a = w.currentReceiveAddress();
        final UTXO utxo = new UTXO(Sha256Hash.of(new byte[] { 1, 2, 3 }), 1, Coin.COIN, 0, false,
                ScriptBuilder.createOutputScript(a));
        w.setUTXOProvider(new UTXOProvider() {
            @Override
            public Network network() {
                return BitcoinNetwork.TESTNET;
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

        Transaction tx2 = new Transaction();
        tx2.addOutput(Coin.valueOf(99000000), new ECKey());
        w.completeTx(SendRequest.forTx(tx2));

        TransactionInput txInToDisconnect = tx2.getInput(0);

        assertNull(txInToDisconnect.getOutpoint().fromTx);
        assertEquals(utxo.getHash(), txInToDisconnect.getOutpoint().connectedOutput.getParentTransactionHash());

        txInToDisconnect.disconnect();

        assertNull(txInToDisconnect.getOutpoint().fromTx);
        assertNull(txInToDisconnect.getOutpoint().connectedOutput);
    }

    @Test
    public void coinbaseInput() {
        TransactionInput coinbaseInput = TransactionInput.coinbaseInput(new Transaction(), new byte[2]);
        assertTrue(coinbaseInput.isCoinBase());
    }

    @Test
    @Parameters(method = "randomInputs")
    public void readAndWrite(TransactionInput input) {
        ByteBuffer buf = ByteBuffer.allocate(input.messageSize());
        input.write(buf);
        assertFalse(buf.hasRemaining());
        ((Buffer) buf).rewind();
        TransactionInput inputCopy = TransactionInput.read(buf, input.getParentTransaction());
        assertFalse(buf.hasRemaining());
        assertEquals(input, inputCopy);
    }

    private Iterator<TransactionInput> randomInputs() {
        Random random = new Random();
        Transaction parent = new Transaction();
        return Stream.generate(() -> {
            byte[] randomBytes = new byte[100];
            random.nextBytes(randomBytes);
            return new TransactionInput(parent, randomBytes, TransactionOutPoint.UNCONNECTED,
                    Coin.ofSat(Math.abs(random.nextLong())));
        }).limit(10).iterator();
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeValue() {
        new TransactionInput(new Transaction(), new byte[0], TransactionOutPoint.UNCONNECTED, Coin.ofSat(-1));
    }
}
