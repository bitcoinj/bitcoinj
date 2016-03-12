package org.bitcoinj.core;

import com.google.common.collect.ImmutableList;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.testing.TestWithWallet;
import org.hamcrest.CoreMatchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

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
        sendMoneyToWallet(Coin.COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        ECKey myKey = new ECKey();
        this.wallet.importKey(myKey);

        // Simulate another signatory
        ECKey otherKey = new ECKey();

        // Create multi-sig transaction
        Transaction multiSigTransaction = new Transaction(PARAMS);
        ImmutableList<ECKey> keys = ImmutableList.of(myKey, otherKey);

        Script scriptPubKey = ScriptBuilder.createMultiSigOutputScript(2, keys);
        multiSigTransaction.addOutput(Coin.COIN, scriptPubKey);

        Wallet.SendRequest req = Wallet.SendRequest.forTx(multiSigTransaction);
        this.wallet.completeTx(req);
        TransactionOutput multiSigTransactionOutput = multiSigTransaction.getOutput(0);

        assertThat(multiSigTransactionOutput.toString(), CoreMatchers.containsString("CHECKMULTISIG"));
    }

    @Test
    public void testP2SHOutputScript() throws Exception {
        String P2SHAddressString = "35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU";
        Address P2SHAddress = Address.fromBase58(MainNetParams.get(), P2SHAddressString);
        Script script = ScriptBuilder.createOutputScript(P2SHAddress);
        Transaction tx = new Transaction(MainNetParams.get());
        tx.addOutput(Coin.COIN, script);
        assertEquals(P2SHAddressString, tx.getOutput(0).getAddressFromP2SH(MainNetParams.get()).toString());
    }

    @Test
    public void getAddressTests() throws Exception {
        Transaction tx = new Transaction(MainNetParams.get());
        tx.addOutput(Coin.CENT, ScriptBuilder.createOpReturnScript("hello world!".getBytes()));
        assertNull(tx.getOutput(0).getAddressFromP2SH(PARAMS));
        assertNull(tx.getOutput(0).getAddressFromP2PKHScript(PARAMS));
    }

    @Test
    public void getMinNonDustValue() throws Exception {
        TransactionOutput payToAddressOutput = new TransactionOutput(PARAMS, null, Coin.COIN, myAddress);
        assertEquals(Transaction.MIN_NONDUST_OUTPUT, payToAddressOutput.getMinNonDustValue());
    }
}
