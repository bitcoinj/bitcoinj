/**
 * Copyright 2012 Google Inc.
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

package com.google.bitcoin.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;

import org.junit.Test;

import com.google.bitcoin.core.BlockChain.NewBlockType;
import com.google.bitcoin.core.Wallet.BalanceType;

/**
 * Test that an example production coinbase transactions can be added to a wallet ok.
 */
public class CoinbaseBlockTest {
    static final NetworkParameters params = NetworkParameters.prodNet();

    // The address for this private key is 1GqtGtn4fctXuKxsVzRPSLmYWN1YioLi9y.
    private static final String MINING_PRIVATE_KEY = "5JDxPrBRghF1EvSBjDigywqfmAjpHPmTJxYtQTYJxJRHLLQA4mG";

    private static final int BLOCK_OF_INTEREST = 169482;
    private static final int BLOCK_LENGTH_AS_HEX = 37357;
    private static final long BLOCK_NONCE = 3973947400L;
    private static final BigInteger BALANCE_AFTER_BLOCK = BigInteger.valueOf(22223642);

    @Test
    public void testReceiveCoinbaseTransaction() throws Exception {
        // Block 169482 (hash 0000000000000756935f1ee9d5987857b604046f846d3df56d024cdb5f368665)
        // contains coinbase transactions that are mining pool shares.
        // The private key MINERS_KEY is used to check transactions are received by a wallet correctly.

        byte[] blockAsBytes = getBytes(getClass().getResourceAsStream("block169482.dat"));

        // Create block 169482.
        Block block = new Block(params, blockAsBytes);

        // Check block.
        assertNotNull(block);
        block.verify();
        assertEquals(BLOCK_NONCE, block.getNonce());

        StoredBlock storedBlock = new StoredBlock(block, BigInteger.ONE, BLOCK_OF_INTEREST); // Nonsense work - not used in test.

        // Create a wallet contain the miner's key that receives a spend from a coinbase.
        ECKey miningKey = (new DumpedPrivateKey(params, MINING_PRIVATE_KEY)).getKey();
        assertNotNull(miningKey);

        Wallet wallet = new Wallet(params);
        wallet.addKey(miningKey);

        // Initial balance should be zero by construction.
        assertEquals(BigInteger.ZERO, wallet.getBalance());

        // Give the wallet the first transaction in the block - this is the coinbase tx.
        List<Transaction> transactions = block.getTransactions();
        assertNotNull(transactions);
        wallet.receiveFromBlock(transactions.get(0), storedBlock, NewBlockType.BEST_CHAIN);

        // Coinbase transaction should have been received successfully but be unavailable to spend (too young).
        assertEquals(BALANCE_AFTER_BLOCK, wallet.getBalance(BalanceType.ESTIMATED));
        assertEquals(BigInteger.ZERO, wallet.getBalance(BalanceType.AVAILABLE));
    }

    /**
     * Returns the contents of the InputStream as a byte array.
     */
    private byte[] getBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        int numberRead;
        byte[] data = new byte[BLOCK_LENGTH_AS_HEX];

        while ((numberRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, numberRead);
        }

        buffer.flush();

        return buffer.toByteArray();
    }
}
