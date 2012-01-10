package com.google.bitcoin.store;


import static com.google.bitcoin.core.TestUtils.createFakeTx;
import static com.google.bitcoin.core.Utils.toNanoCoins;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.BlockChain;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.core.WalletTransaction;

import static org.junit.Assert.*;

public class WalletProtobufSerializerTest {
    static final NetworkParameters params = NetworkParameters.unitTests();
    private ECKey myKey;
    private Address myAddress;
    private Wallet wallet;
    private MemoryBlockStore blockStore;

    @Before
    public void setUp() throws Exception {
        myKey = new ECKey();
        myAddress = myKey.toAddress(params);
        wallet = new Wallet(params);
        wallet.addKey(myKey);
        blockStore = new MemoryBlockStore(params);
    }

    @Test
    public void testSimple() throws Exception {
        Wallet wallet1 = roundTrip(wallet);
        assertEquals(0, wallet1.getTransactions(true, true).size());
        assertEquals(BigInteger.ZERO, wallet1.getBalance());
        
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(params, v1, myAddress);

        wallet.receiveFromBlock(t1, null, BlockChain.NewBlockType.BEST_CHAIN);
        
        wallet1 = roundTrip(wallet);
        assertEquals(1, wallet1.getTransactions(true, true).size());
        assertEquals(v1, wallet1.getBalance());
        assertArrayEquals(t1.bitcoinSerialize(), wallet1.getTransaction(t1.getHash()).bitcoinSerialize());
        
        ECKey k2 = new ECKey();
        BigInteger v2 = toNanoCoins(0, 50);
        Transaction t2 = wallet.sendCoinsOffline(k2.toAddress(params), v2);
        wallet1 = roundTrip(wallet);
        assertArrayEquals(t2.bitcoinSerialize(), wallet1.getTransaction(t2.getHash()).bitcoinSerialize());

        assertEquals(1, wallet1.getPendingTransactions().size());
        assertEquals(2, wallet1.getTransactions(true, true).size());
    }

    private Wallet roundTrip(Wallet wallet) throws IOException, AddressFormatException, BlockStoreException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        //System.out.println(WalletProtobufSerializer.walletToText(wallet));
        WalletProtobufSerializer.writeWallet(wallet, output);
        ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());
        return WalletProtobufSerializer.readWallet(input, params, blockStore);
    }
}
