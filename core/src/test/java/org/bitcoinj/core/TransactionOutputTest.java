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

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.testing.TestWithWallet;
import org.bitcoinj.wallet.SendRequest;
import org.hamcrest.CoreMatchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class TransactionOutputTest extends TestWithWallet {

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void testMultiSigOutputToString() throws Exception {
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, Coin.COIN);
        ECKey myKey = new ECKey();
        this.wallet.importKey(myKey);

        // Simulate another signatory
        ECKey otherKey = new ECKey();

        // Create multi-sig transaction
        Transaction multiSigTransaction = new Transaction(TESTNET);
        List<ECKey> keys = Arrays.asList(myKey, otherKey);

        Script scriptPubKey = ScriptBuilder.createMultiSigOutputScript(2, keys);
        multiSigTransaction.addOutput(Coin.COIN, scriptPubKey);

        SendRequest req = SendRequest.forTx(multiSigTransaction);
        this.wallet.completeTx(req);
        TransactionOutput multiSigTransactionOutput = multiSigTransaction.getOutput(0);

        assertThat(multiSigTransactionOutput.toString(), CoreMatchers.containsString("CHECKMULTISIG"));
    }

    @Test
    public void testP2SHOutputScript() {
        String P2SHAddressString = "35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU";
        Address P2SHAddress = LegacyAddress.fromBase58(BitcoinNetwork.MAINNET, P2SHAddressString);
        Script script = ScriptBuilder.createOutputScript(P2SHAddress);
        Transaction tx = new Transaction(MAINNET);
        tx.addOutput(Coin.COIN, script);
        assertEquals(P2SHAddressString, tx.getOutput(0).getScriptPubKey().getToAddress(MAINNET).toString());
    }

    @Test
    public void getAddressTests() {
        Transaction tx = new Transaction(MAINNET);
        tx.addOutput(Coin.CENT, ScriptBuilder.createOpReturnScript("hello world!".getBytes()));
        assertTrue(ScriptPattern.isOpReturn(tx.getOutput(0).getScriptPubKey()));
        assertFalse(ScriptPattern.isP2PK(tx.getOutput(0).getScriptPubKey()));
        assertFalse(ScriptPattern.isP2PKH(tx.getOutput(0).getScriptPubKey()));
    }

    @Test
    public void getMinNonDustValue() {
        TransactionOutput p2pk = new TransactionOutput(TESTNET, null, Coin.COIN, myKey);
        assertEquals(Coin.valueOf(576), p2pk.getMinNonDustValue());
        TransactionOutput p2pkh = new TransactionOutput(TESTNET, null, Coin.COIN, myKey.toAddress(ScriptType.P2PKH,
                BitcoinNetwork.TESTNET));
        assertEquals(Coin.valueOf(546), p2pkh.getMinNonDustValue());
        TransactionOutput p2wpkh = new TransactionOutput(TESTNET, null, Coin.COIN, myKey.toAddress(ScriptType.P2WPKH,
                BitcoinNetwork.TESTNET));
        assertEquals(Coin.valueOf(294), p2wpkh.getMinNonDustValue());
    }
}
