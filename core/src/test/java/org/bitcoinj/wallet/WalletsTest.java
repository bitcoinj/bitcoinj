package org.bitcoinj.wallet;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.testing.TestWithWallet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


import static org.bitcoinj.base.Coin.valueOf;
import static org.bitcoinj.testing.FakeTxBuilder.*;
import static org.junit.Assert.assertEquals;

public class WalletsTest extends TestWithWallet {

    protected Wallet wallet2;
    protected Address myAddress2;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        wallet2 = Wallet.createDeterministic(TESTNET, ScriptType.P2PKH, KeyChainGroupStructure.BIP32);
        myAddress2 = wallet2.freshReceiveAddress(ScriptType.P2PKH);
        chain.addWallet(wallet2);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void sharedTransactionCorrectDepth() throws Exception {

        // ARRANGE //
        Coin v1 = valueOf(5, 0);
        Coin v2 = valueOf(0, 50);
        Coin v3 = valueOf(0, 25);

        Transaction t1 = createFakeTxWithChangeAddress(TESTNET, v1, myAddress, myAddress2);
        Transaction t2 = createFakeTxWithChangeAddress(TESTNET, v2, myAddress, myAddress2);
        Transaction t3 = createFakeTxWithChangeAddress(TESTNET, v3, myAddress, myAddress2);

        Block genesis = blockStore.getChainHead().getHeader();
        Block b1 = makeSolvedTestBlock(genesis, t1);
        Block b2 = makeSolvedTestBlock(b1, t2);
        Block b3 = makeSolvedTestBlock(b2, t3);

        // ACT //
        chain.add(b1);
        chain.add(b2);
        chain.add(b3);

        // ASSERT //
        Transaction tx1 = wallet.getTransaction(t1.getTxId());
        Transaction tx2 = wallet.getTransaction(t2.getTxId());
        Transaction tx3 = wallet.getTransaction(t3.getTxId());

        assertEquals(3, tx1.getConfidence().getDepthInBlocks());
        assertEquals(2, tx2.getConfidence().getDepthInBlocks());
        assertEquals(1, tx3.getConfidence().getDepthInBlocks());
    }
}
