/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

import com.google.common.io.ByteStreams;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.AbstractBlockChain.NewBlockType;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.BalanceType;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import static org.bitcoinj.base.utils.ByteUtils.HEX;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class BlockTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private byte[] block700000Bytes;
    private Block block700000;

    @Before
    public void setUp() throws Exception {
        // One with some of transactions in, so a good test of the merkle tree hashing.
        block700000Bytes = ByteStreams.toByteArray(BlockTest.class.getResourceAsStream("block_testnet700000.dat"));
        block700000 = TESTNET.getDefaultSerializer().makeBlock(block700000Bytes);
        assertEquals("000000000000406178b12a4dea3b27e13b3c4fe4510994fd667d7c1e6a3f4dc1", block700000.getHashAsString());
    }

    @Test
    public void testWork() {
        BigInteger work = TESTNET.getGenesisBlock().getWork();
        double log2Work = Math.log(work.longValue()) / Math.log(2);
        // This number is printed by Bitcoin Core at startup as the calculated value of chainWork on testnet:
        // UpdateTip: new best=000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943 height=0 version=0x00000001 log2_work=32.000022 tx=1 date='2011-02-02 23:16:42' ...
        assertEquals(32.000022, log2Work, 0.0000001);
    }

    @Test
    public void testBlockVerification() {
        block700000.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
    }
    
    @Test
    public void testDate() {
        assertEquals("2016-02-13T22:59:39Z", Utils.dateTimeFormat(block700000.getTime()));
    }

    @Test
    public void testProofOfWork() {
        // This params accepts any difficulty target.
        Block block = UNITTEST.getDefaultSerializer().makeBlock(block700000Bytes);
        block.setNonce(12346);
        try {
            block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
            fail();
        } catch (VerificationException e) {
            // Expected.
        }
        // Blocks contain their own difficulty target. The BlockChain verification mechanism is what stops real blocks
        // from containing artificially weak difficulties.
        block.setDifficultyTarget(Block.EASIEST_DIFFICULTY_TARGET);
        // Now it should pass.
        block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
        // Break the nonce again at the lower difficulty level so we can try solving for it.
        block.setNonce(1);
        try {
            block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
            fail();
        } catch (VerificationException e) {
            // Expected to fail as the nonce is no longer correct.
        }
        // Should find an acceptable nonce.
        block.solve();
        block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
    }

    @Test
    public void testBadTransactions() {
        // Re-arrange so the coinbase transaction is not first.
        Transaction tx1 = block700000.transactions.get(0);
        Transaction tx2 = block700000.transactions.get(1);
        block700000.transactions.set(0, tx2);
        block700000.transactions.set(1, tx1);
        try {
            block700000.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
            fail();
        } catch (VerificationException e) {
            // We should get here.
        }
    }

    @Test
    public void testHeaderParse() {
        Block header = block700000.cloneAsHeader();
        Block reparsed = TESTNET.getDefaultSerializer().makeBlock(header.bitcoinSerialize());
        assertEquals(reparsed, header);
    }

    @Test
    public void testBitcoinSerialization() {
        // We have to be able to reserialize everything exactly as we found it for hashing to work. This test also
        // proves that transaction serialization works, along with all its subobjects like scripts and in/outpoints.
        //
        // NB: This tests the bitcoin serialization protocol.
        assertArrayEquals(block700000Bytes, block700000.bitcoinSerialize());
    }
    
    @Test
    public void testUpdateLength() {
        Block block = UNITTEST.getGenesisBlock().createNextBlockWithCoinbase(Block.BLOCK_VERSION_GENESIS, new ECKey().getPubKey(), Block.BLOCK_HEIGHT_GENESIS);
        assertEquals(block.bitcoinSerialize().length, block.length);
        final int origBlockLen = block.length;
        Transaction tx = new Transaction(UNITTEST);
        // this is broken until the transaction has > 1 input + output (which is required anyway...)
        //assertTrue(tx.length == tx.bitcoinSerialize().length && tx.length == 8);
        byte[] outputScript = new byte[10];
        Arrays.fill(outputScript, (byte) ScriptOpCodes.OP_FALSE);
        tx.addOutput(new TransactionOutput(UNITTEST, null, Coin.SATOSHI, outputScript));
        tx.addInput(new TransactionInput(UNITTEST, null, new byte[] {(byte) ScriptOpCodes.OP_FALSE},
                new TransactionOutPoint(UNITTEST, 0, Sha256Hash.of(new byte[] { 1 }))));
        int origTxLength = 8 + 2 + 8 + 1 + 10 + 40 + 1 + 1;
        assertEquals(tx.unsafeBitcoinSerialize().length, tx.length);
        assertEquals(origTxLength, tx.length);
        block.addTransaction(tx);
        assertEquals(block.unsafeBitcoinSerialize().length, block.length);
        assertEquals(origBlockLen + tx.length, block.length);
        block.getTransactions().get(1).getInputs().get(0).setScriptBytes(new byte[] {(byte) ScriptOpCodes.OP_FALSE, (byte) ScriptOpCodes.OP_FALSE});
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength + 1);
        block.getTransactions().get(1).getInputs().get(0).clearScriptBytes();
        assertEquals(block.length, block.unsafeBitcoinSerialize().length);
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength - 1);
        block.getTransactions().get(1).addInput(new TransactionInput(UNITTEST, null, new byte[] {(byte) ScriptOpCodes.OP_FALSE},
                new TransactionOutPoint(UNITTEST, 0, Sha256Hash.of(new byte[] { 1 }))));
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength + 41); // - 1 + 40 + 1 + 1
    }

    @Test
    public void testCoinbaseHeightTestnet() throws Exception {
        // Testnet block 21066 (hash 0000000004053156021d8e42459d284220a7f6e087bf78f30179c3703ca4eefa)
        // contains a coinbase transaction whose height is two bytes, which is
        // shorter than we see in most other cases.

        Block block = TESTNET.getDefaultSerializer().makeBlock(
            ByteStreams.toByteArray(getClass().getResourceAsStream("block_testnet21066.dat")));

        // Check block.
        assertEquals("0000000004053156021d8e42459d284220a7f6e087bf78f30179c3703ca4eefa", block.getHashAsString());
        block.verify(21066, EnumSet.of(Block.VerifyFlag.HEIGHT_IN_COINBASE));

        // Testnet block 32768 (hash 000000007590ba495b58338a5806c2b6f10af921a70dbd814e0da3c6957c0c03)
        // contains a coinbase transaction whose height is three bytes, but could
        // fit in two bytes. This test primarily ensures script encoding checks
        // are applied correctly.

        block = TESTNET.getDefaultSerializer().makeBlock(
            ByteStreams.toByteArray(getClass().getResourceAsStream("block_testnet32768.dat")));

        // Check block.
        assertEquals("000000007590ba495b58338a5806c2b6f10af921a70dbd814e0da3c6957c0c03", block.getHashAsString());
        block.verify(32768, EnumSet.of(Block.VerifyFlag.HEIGHT_IN_COINBASE));
    }

    @Test
    public void testReceiveCoinbaseTransaction() throws Exception {
        // Block 169482 (hash 0000000000000756935f1ee9d5987857b604046f846d3df56d024cdb5f368665)
        // contains coinbase transactions that are mining pool shares.
        // The private key MINERS_KEY is used to check transactions are received by a wallet correctly.

        // The address for this private key is 1GqtGtn4fctXuKxsVzRPSLmYWN1YioLi9y.
        final String MINING_PRIVATE_KEY = "5JDxPrBRghF1EvSBjDigywqfmAjpHPmTJxYtQTYJxJRHLLQA4mG";

        final long BLOCK_NONCE = 3973947400L;
        final Coin BALANCE_AFTER_BLOCK = Coin.valueOf(22223642);
        Block block169482 = MAINNET.getDefaultSerializer().makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block169482.dat")));

        // Check block.
        assertNotNull(block169482);
        block169482.verify(169482, EnumSet.noneOf(Block.VerifyFlag.class));
        assertEquals(BLOCK_NONCE, block169482.getNonce());

        StoredBlock storedBlock = new StoredBlock(block169482, BigInteger.ONE, 169482); // Nonsense work - not used in test.

        // Create a wallet contain the miner's key that receives a spend from a coinbase.
        ECKey miningKey = DumpedPrivateKey.fromBase58(MAINNET, MINING_PRIVATE_KEY).getKey();
        assertNotNull(miningKey);
        Wallet wallet = Wallet.createDeterministic(MAINNET, ScriptType.P2PKH);
        wallet.importKey(miningKey);

        // Initial balance should be zero by construction.
        assertEquals(Coin.ZERO, wallet.getBalance());

        // Give the wallet the first transaction in the block - this is the coinbase tx.
        List<Transaction> transactions = block169482.getTransactions();
        assertNotNull(transactions);
        wallet.receiveFromBlock(transactions.get(0), storedBlock, NewBlockType.BEST_CHAIN, 0);

        // Coinbase transaction should have been received successfully but be unavailable to spend (too young).
        assertEquals(BALANCE_AFTER_BLOCK, wallet.getBalance(BalanceType.ESTIMATED));
        assertEquals(Coin.ZERO, wallet.getBalance(BalanceType.AVAILABLE));
    }

    @Test
    public void testBlock481815_witnessCommitmentInCoinbase() throws Exception {
        Block block481815 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block481815.dat")));
        assertEquals(2097, block481815.getTransactions().size());
        assertEquals("f115afa8134171a0a686bfbe9667b60ae6fb5f6a439e0265789babc315333262",
                block481815.getMerkleRoot().toString());

        // This block has no witnesses.
        for (Transaction tx : block481815.getTransactions())
            assertFalse(tx.hasWitnesses());

        // Nevertheless, there is a witness commitment (but no witness reserved).
        Transaction coinbase = block481815.getTransactions().get(0);
        assertEquals("919a0df2253172a55bebcb9002dbe775b8511f84955b282ca6dae826fdd94f90", coinbase.getTxId().toString());
        assertEquals("919a0df2253172a55bebcb9002dbe775b8511f84955b282ca6dae826fdd94f90",
                coinbase.getWTxId().toString());
        Sha256Hash witnessCommitment = coinbase.findWitnessCommitment();
        assertEquals("3d03076733467c45b08ec503a0c5d406647b073e1914d35b5111960ed625f3b7", witnessCommitment.toString());
    }

    @Test
    public void testBlock481829_witnessTransactions() throws Exception {
        Block block481829 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block481829.dat")));
        assertEquals(2020, block481829.getTransactions().size());
        assertEquals("f06f697be2cac7af7ed8cd0b0b81eaa1a39e444c6ebd3697e35ab34461b6c58d",
                block481829.getMerkleRoot().toString());
        assertEquals("0a02ddb2f86a14051294f8d98dd6959dd12bf3d016ca816c3db9b32d3e24fc2d",
                block481829.getWitnessRoot().toString());

        Transaction coinbase = block481829.getTransactions().get(0);
        assertEquals("9c1ab453283035800c43eb6461eb46682b81be110a0cb89ee923882a5fd9daa4", coinbase.getTxId().toString());
        assertEquals("2bbda73aa4e561e7f849703994cc5e563e4bcf103fb0f6fef5ae44c95c7b83a6",
                coinbase.getWTxId().toString());
        Sha256Hash witnessCommitment = coinbase.findWitnessCommitment();
        assertEquals("c3c1145d8070a57e433238e42e4c022c1e51ca2a958094af243ae1ee252ca106", witnessCommitment.toString());
        byte[] witnessReserved = coinbase.getInput(0).getWitness().getPush(0);
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", HEX.encode(witnessReserved));
        block481829.checkWitnessRoot();
    }

    @Test
    public void isBIPs() throws Exception {
        final Block genesis = MAINNET.getGenesisBlock();
        assertFalse(genesis.isBIP34());
        assertFalse(genesis.isBIP66());
        assertFalse(genesis.isBIP65());

        // 227835/00000000000001aa077d7aa84c532a4d69bdbff519609d1da0835261b7a74eb6: last version 1 block
        final Block block227835 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227835.dat")));
        assertFalse(block227835.isBIP34());
        assertFalse(block227835.isBIP66());
        assertFalse(block227835.isBIP65());

        // 227836/00000000000000d0dfd4c9d588d325dce4f32c1b31b7c0064cba7025a9b9adcc: version 2 block
        final Block block227836 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227836.dat")));
        assertTrue(block227836.isBIP34());
        assertFalse(block227836.isBIP66());
        assertFalse(block227836.isBIP65());

        // 363703/0000000000000000011b2a4cb91b63886ffe0d2263fd17ac5a9b902a219e0a14: version 3 block
        final Block block363703 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block363703.dat")));
        assertTrue(block363703.isBIP34());
        assertTrue(block363703.isBIP66());
        assertFalse(block363703.isBIP65());

        // 383616/00000000000000000aab6a2b34e979b09ca185584bd1aecf204f24d150ff55e9: version 4 block
        final Block block383616 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block383616.dat")));
        assertTrue(block383616.isBIP34());
        assertTrue(block383616.isBIP66());
        assertTrue(block383616.isBIP65());

        // 370661/00000000000000001416a613602d73bbe5c79170fd8f39d509896b829cf9021e: voted for BIP101
        final Block block370661 = MAINNET.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block370661.dat")));
        assertTrue(block370661.isBIP34());
        assertTrue(block370661.isBIP66());
        assertTrue(block370661.isBIP65());
    }

    @Test
    public void parseBlockWithHugeDeclaredTransactionsSize() {
        Block block = new Block(UNITTEST, 1, Sha256Hash.ZERO_HASH, Sha256Hash.ZERO_HASH, 1, 1, 1, new ArrayList<Transaction>()) {
            @Override
            protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
                ByteUtils.uint32ToByteStreamLE(getVersion(), stream);
                stream.write(getPrevBlockHash().getReversedBytes());
                stream.write(getMerkleRoot().getReversedBytes());
                ByteUtils.uint32ToByteStreamLE(getTimeSeconds(), stream);
                ByteUtils.uint32ToByteStreamLE(getDifficultyTarget(), stream);
                ByteUtils.uint32ToByteStreamLE(getNonce(), stream);

                stream.write(new VarInt(Integer.MAX_VALUE).encode());
            }

            @Override
            public byte[] bitcoinSerialize() {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    bitcoinSerializeToStream(baos);
                } catch (IOException e) {
                }
                return baos.toByteArray();
            }
        };
        byte[] serializedBlock = block.bitcoinSerialize();
        try {
            UNITTEST.getDefaultSerializer().makeBlock(serializedBlock, serializedBlock.length);
            fail("We expect ProtocolException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (ProtocolException e) {
            //Expected, do nothing
        }
    }

    @Test
    public void testGenesisBlock() {
        Block genesisBlock = Block.createGenesis(MainNetParams.get());
        genesisBlock.setDifficultyTarget(0x1d00ffffL);
        genesisBlock.setTime(1231006505L);
        genesisBlock.setNonce(2083236893);
        assertEquals(Sha256Hash.wrap("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"), genesisBlock.getHash());
    }
}
