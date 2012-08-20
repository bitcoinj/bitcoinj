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
import java.net.InetAddress;
import java.util.*;

import static com.google.bitcoin.core.TestUtils.createFakeTx;
import static org.junit.Assert.*;

public class WalletProtobufSerializerTest {
    static final NetworkParameters params = NetworkParameters.unitTests();
    private ECKey myKey;
    private Address myAddress;
    private Wallet myWallet;

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.initVerbose();
        myKey = new ECKey();
        myKey.setCreationTimeSeconds(123456789L);
        myAddress = myKey.toAddress(params);
        myWallet = new Wallet(params);
        myWallet.addKey(myKey);
    }

    @Test
    public void empty() throws Exception {
        // Check the base case of a wallet with one key and no transactions.
        Wallet wallet1 = roundTrip(myWallet);
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
        t1.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByName("1.2.3.4")));
        t1.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByName("5.6.7.8")));
        myWallet.receiveFromBlock(t1, null, BlockChain.NewBlockType.BEST_CHAIN);
        Wallet wallet1 = roundTrip(myWallet);
        assertEquals(1, wallet1.getTransactions(true, true).size());
        assertEquals(v1, wallet1.getBalance());
        assertArrayEquals(t1.bitcoinSerialize(),
                wallet1.getTransaction(t1.getHash()).bitcoinSerialize());
        assertEquals(2, wallet1.getTransaction(t1.getHash()).getConfidence().numBroadcastPeers());
        
        Protos.Wallet walletProto = new WalletProtobufSerializer().walletToProto(myWallet);
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
        myWallet.receivePending(doubleSpends.t1);
        // t2 rolls back t1 and spends somewhere else.
        myWallet.receiveFromBlock(doubleSpends.t2, null, BlockChain.NewBlockType.BEST_CHAIN);
        Wallet wallet1 = roundTrip(myWallet);
        assertEquals(1, wallet1.getTransactions(true, true).size());
        Transaction t1 = wallet1.getTransaction(doubleSpends.t1.getHash());
        assertEquals(ConfidenceType.DEAD, t1.getConfidence().getConfidenceType());
        assertEquals(BigInteger.ZERO, wallet1.getBalance());

        // TODO: Wallet should store overriding transactions even if they are not wallet-relevant.
        // assertEquals(doubleSpends.t2, t1.getConfidence().getOverridingTransaction());
    }
    
    @Test
    public void testKeys() throws Exception {
        for (int i = 0 ; i < 20 ; i++) {
            myKey = new ECKey();
            myAddress = myKey.toAddress(params);
            myWallet = new Wallet(params);
            myWallet.addKey(myKey);
            Wallet wallet1 = roundTrip(myWallet);
            assertArrayEquals(myKey.getPubKey(), wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPubKey());
            assertArrayEquals(myKey.getPrivKeyBytes(), wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPrivKeyBytes());
        }
    }

    @Test
    public void testLastBlockSeenHash() throws Exception {
        // Test the lastBlockSeenHash field works.

        // LastBlockSeenHash should be empty if never set.
        Wallet wallet = new Wallet(params);
        Protos.Wallet walletProto = new WalletProtobufSerializer().walletToProto(wallet);
        ByteString lastSeenBlockHash = walletProto.getLastSeenBlockHash();
        assertTrue(lastSeenBlockHash.isEmpty());

        // Create a block.
        Block block = new Block(params, BlockTest.blockBytes);
        Sha256Hash blockHash = block.getHash();
        wallet.setLastBlockSeenHash(blockHash);

        // Roundtrip the wallet and check it has stored the blockHash.
        Wallet wallet1 = roundTrip(wallet);
        assertEquals(blockHash, wallet1.getLastBlockSeenHash());

        // Test the Satoshi genesis block (hash of all zeroes) is roundtripped ok.
        Block genesisBlock = NetworkParameters.prodNet().genesisBlock;
        wallet.setLastBlockSeenHash(genesisBlock.getHash());
        Wallet wallet2 = roundTrip(wallet);
        assertEquals(genesisBlock.getHash(), wallet2.getLastBlockSeenHash());
    }

    @Test
    public void testAppearedAtChainHeightDepthAndWorkDone() throws Exception {
        // Test the TransactionConfidence appearedAtChainHeight, depth and workDone field are stored.

        BlockChain chain = new BlockChain(params, myWallet, new MemoryBlockStore(params));

        final ArrayList<Transaction> txns = new ArrayList<Transaction>(2);
        myWallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                txns.add(tx);
            }
        });

        // Start by building two blocks on top of the genesis block.
        Block b1 = params.genesisBlock.createNextBlock(myAddress);
        BigInteger work1 = b1.getWork();
        assertTrue(work1.compareTo(BigInteger.ZERO) > 0);

        Block b2 = b1.createNextBlock(myAddress);
        BigInteger work2 = b2.getWork();
        assertTrue(work2.compareTo(BigInteger.ZERO) > 0);

        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));

        // We now have the following chain:
        //     genesis -> b1 -> b2

        // Check the transaction confidence levels are correct before wallet roundtrip.
        assertEquals(2, txns.size());

        TransactionConfidence confidence0 = txns.get(0).getConfidence();
        TransactionConfidence confidence1 = txns.get(1).getConfidence();

        assertEquals(1, confidence0.getAppearedAtChainHeight());
        assertEquals(2, confidence1.getAppearedAtChainHeight());

        assertEquals(2, confidence0.getDepthInBlocks());
        assertEquals(1, confidence1.getDepthInBlocks());

        assertEquals(work1.add(work2), confidence0.getWorkDone());
        assertEquals(work2, confidence1.getWorkDone());

        // Roundtrip the wallet and check it has stored the depth and workDone.
        Wallet rebornWallet = roundTrip(myWallet);

        Set<Transaction> rebornTxns = rebornWallet.getTransactions(false, false);
        assertEquals(2, rebornTxns.size());

        // The transactions are not guaranteed to be in the same order so sort them to be in chain height order if required.
        Iterator<Transaction> it = rebornTxns.iterator();
        Transaction txA = it.next();
        Transaction txB = it.next();

        Transaction rebornTx0, rebornTx1;
         if (txA.getConfidence().getAppearedAtChainHeight() == 1) {
            rebornTx0 = txA;
            rebornTx1 = txB;
        } else {
            rebornTx0 = txB;
            rebornTx1 = txA;
        }

        TransactionConfidence rebornConfidence0 = rebornTx0.getConfidence();
        TransactionConfidence rebornConfidence1 = rebornTx1.getConfidence();

        assertEquals(1, rebornConfidence0.getAppearedAtChainHeight());
        assertEquals(2, rebornConfidence1.getAppearedAtChainHeight());

        assertEquals(2, rebornConfidence0.getDepthInBlocks());
        assertEquals(1, rebornConfidence1.getDepthInBlocks());

        assertEquals(work1.add(work2), rebornConfidence0.getWorkDone());
        assertEquals(work2, rebornConfidence1.getWorkDone());
    }

    private Wallet roundTrip(Wallet wallet) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        //System.out.println(WalletProtobufSerializer.walletToText(wallet));
        new WalletProtobufSerializer().writeWallet(wallet, output);
        ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());
        return new WalletProtobufSerializer().readWallet(input);
    }


    @Test
    public void testSerializedExtensionNormalWallet() throws Exception {
        Wallet wallet1 = roundTrip(myWallet);     
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
    public void testSerializedExtensionFancyWallet() throws Exception {
        Random rnd = new Random();
        WalletExtension wallet1 = new WalletExtension(params);
        wallet1.addKey(myKey);
        wallet1.random_bytes = new byte[100];
        rnd.nextBytes(wallet1.random_bytes);

        Wallet wallet2 = roundTripExtension(wallet1);
        assertTrue(wallet2 instanceof WalletExtension);

        WalletExtension wallet2ext = (WalletExtension)wallet2;

        assertNotNull(wallet2ext.random_bytes);

        for (int i = 0; i < 100; i++) {
            assertEquals(wallet1.random_bytes[i], wallet2ext.random_bytes[i]);
        }
    }

    @Test
    public void testSerializedExtensionFancyWalletRegularTrip() throws Exception {
        Random rnd = new Random();
        WalletExtension wallet1 = new WalletExtension(params);
        wallet1.addKey(myKey);
        wallet1.random_bytes=new byte[100];
        rnd.nextBytes(wallet1.random_bytes);

        Wallet wallet2 = roundTrip(myWallet);
        assertFalse(wallet2 instanceof WalletExtension);

    }


    private Wallet roundTripExtension(Wallet wallet) throws IOException {

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        WalletProtobufSerializer serializer = new WalletProtobufSerializer();
        serializer.setWalletExtensionSerializer(new WalletExtensionSerializerRandom());
        serializer.writeWallet(wallet, output);

        ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());
        return serializer.readWallet(input);
    }


    /**
     * An extension of a wallet that stores a number.
     */
    public class WalletExtension extends Wallet {
        public byte[] random_bytes;

        public WalletExtension(NetworkParameters params) {
            super(params);
        }
    }

    public class WalletExtensionSerializerRandom extends WalletExtensionSerializer {
        @Override
        public Collection<Protos.Extension> getExtensionsToWrite(Wallet wallet) {
            List<Protos.Extension> lst = new LinkedList<Protos.Extension>();
            if (wallet instanceof WalletExtension) {
                WalletExtension walletExt = (WalletExtension) wallet;
                Protos.Extension.Builder e = Protos.Extension.newBuilder();
                e.setId("WalletExtension.random_bytes");
                e.setMandatory(false);
                e.setData(ByteString.copyFrom(walletExt.random_bytes));
                lst.add(e.build());
            }
            lst.addAll(super.getExtensionsToWrite(wallet));
            return lst;
        }

        @Override
        public Wallet newWallet(NetworkParameters params) {
            return new WalletExtension(params);
        }
        
        @Override
        public void readExtension(Wallet wallet, Protos.Extension extProto) {
            if (wallet instanceof WalletExtension) {
                WalletExtension walletExt = (WalletExtension) wallet;
                if (extProto.getId().equals("WalletExtension.random_bytes")) {
                    walletExt.random_bytes = extProto.getData().toByteArray();
                    return;
                }
            }
            super.readExtension(wallet, extProto);
        }
    }
}
