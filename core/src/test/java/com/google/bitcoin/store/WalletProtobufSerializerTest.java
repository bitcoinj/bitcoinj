package com.google.bitcoin.store;


import com.google.bitcoin.core.*;
import com.google.bitcoin.core.TransactionConfidence.ConfidenceType;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.protobuf.ByteString;

import org.bitcoinj.wallet.Protos;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import static com.google.bitcoin.core.TestUtils.createFakeTx;
import static org.junit.Assert.*;

public class WalletProtobufSerializerTest {
    static final NetworkParameters params = NetworkParameters.unitTests();
    private ECKey myKey;
    private Address myAddress;
    private Wallet wallet;

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.initVerbose();
        myKey = new ECKey();
        myKey.setCreationTimeSeconds(123456789L);
        myAddress = myKey.toAddress(params);
        wallet = new Wallet(params);
        wallet.addKey(myKey);
    }

    @Test
    public void empty() throws Exception {
        // Check the base case of a wallet with one key and no transactions.
        Wallet wallet1 = roundTrip(wallet);
        assertEquals(0, wallet1.getTransactions(true, true).size());
        assertEquals(BigInteger.ZERO, wallet1.getBalance());
        assertArrayEquals(myKey.getPubKey(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPubKey());
        assertArrayEquals(myKey.getPrivKeyBytes(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPrivKeyBytes());
        assertEquals(myKey.getCreationTimeSeconds(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getCreationTimeSeconds());
    }

    @Test
    public void oneTx() throws Exception {
        // Check basic tx serialization.
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(params, v1, myAddress);

        wallet.receiveFromBlock(t1, null, BlockChain.NewBlockType.BEST_CHAIN);
        Wallet wallet1 = roundTrip(wallet);
        assertEquals(1, wallet1.getTransactions(true, true).size());
        assertEquals(v1, wallet1.getBalance());
        assertArrayEquals(t1.bitcoinSerialize(),
                wallet1.getTransaction(t1.getHash()).bitcoinSerialize());
        
        Protos.Wallet walletProto = WalletProtobufSerializer.walletToProto(wallet);
        assertEquals(Protos.Key.Type.ORIGINAL, walletProto.getKey(0).getType());
        assertEquals(0, walletProto.getExtensionCount());
        assertEquals(1, walletProto.getTransactionCount());
        assertEquals(1, walletProto.getKeyCount());
        
        Protos.Transaction t1p = walletProto.getTransaction(0);
        assertEquals(0, t1p.getBlockHashCount());
        assertArrayEquals(t1.getHash().getBytes(), t1p.getHash().toByteArray());
        assertEquals(Protos.Transaction.Pool.UNSPENT, t1p.getPool());
        assertFalse(t1p.hasLockTime());
        assertFalse(t1p.getTransactionInput(0).hasSequence());
        assertArrayEquals(t1.getInputs().get(0).getOutpoint().getHash().getBytes(),
                t1p.getTransactionInput(0).getTransactionOutPointHash().toByteArray());
        assertEquals(0, t1p.getTransactionInput(0).getTransactionOutPointIndex());
        assertEquals(t1p.getTransactionOutput(0).getValue(), v1.longValue());
    }

    @Test
    public void doubleSpend() throws Exception {
        // Check that we can serialize double spends correctly, as this is a slightly tricky case.
        TestUtils.DoubleSpends doubleSpends = TestUtils.createFakeDoubleSpendTxns(params, myAddress);
        // t1 spends to our wallet.
        wallet.receivePending(doubleSpends.t1);
        // t2 rolls back t1 and spends somewhere else.
        wallet.receiveFromBlock(doubleSpends.t2, null, BlockChain.NewBlockType.BEST_CHAIN);
        Wallet wallet1 = roundTrip(wallet);
        assertEquals(1, wallet1.getTransactions(true, true).size());
        Transaction t1 = wallet1.getTransaction(doubleSpends.t1.getHash());
        assertEquals(ConfidenceType.OVERRIDDEN_BY_DOUBLE_SPEND, t1.getConfidence().getConfidenceType());
        assertEquals(BigInteger.ZERO, wallet1.getBalance());

        // TODO: Wallet should store overriding transactions even if they are not wallet-relevant.
        // assertEquals(doubleSpends.t2, t1.getConfidence().getOverridingTransaction());
    }
    
    @Test
    public void testKeys() throws Exception {
        for (int i = 0 ; i < 20 ; i++) {
            myKey = new ECKey();
            myAddress = myKey.toAddress(params);
            wallet = new Wallet(params);
            wallet.addKey(myKey);
            Wallet wallet1 = roundTrip(wallet);
            assertArrayEquals(myKey.getPubKey(), wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPubKey());
            assertArrayEquals(myKey.getPrivKeyBytes(), wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPrivKeyBytes());
        }
    }

    @Test
    public void testLastBlockSeenHash() throws Exception {
        // Test the lastBlockSeenHash field works.

        // LastBlockSeenHash should be empty if never set.
        wallet = new Wallet(params);
        Protos.Wallet walletProto = WalletProtobufSerializer.walletToProto(wallet);
        ByteString lastSeenBlockHash = walletProto.getLastSeenBlockHash();
        assertTrue(lastSeenBlockHash.isEmpty());

        // Create a block.
        Block block = new Block(params, BlockTest.blockBytes);
        Sha256Hash blockHash = block.getHash();
        wallet.setLastBlockSeenHash(blockHash);

        // Roundtrip the wallet and check it has stored te blockHash.
        Wallet wallet1 = roundTrip(wallet);
        assertEquals(blockHash, wallet1.getLastBlockSeenHash());

        // Test the Satoshi genesis block (hash of all zeroes) is roundtripped ok.
        Block genesisBlock = NetworkParameters.prodNet().genesisBlock;
        wallet.setLastBlockSeenHash(genesisBlock.getHash());
        Wallet wallet2 = roundTrip(wallet);
        assertEquals(genesisBlock.getHash(), wallet2.getLastBlockSeenHash());
    }

    private Wallet roundTrip(Wallet wallet) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        //System.out.println(WalletProtobufSerializer.walletToText(wallet));
        WalletProtobufSerializer.writeWallet(wallet, output);
        ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());
        return WalletProtobufSerializer.readWallet(input);
    }
}
