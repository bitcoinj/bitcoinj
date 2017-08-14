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

package org.bitcoincashj.core;

import com.google.common.io.ByteStreams;

import org.bitcoincashj.core.AbstractBlockChain.NewBlockType;
import org.bitcoincashj.params.MainNetParams;
import org.bitcoincashj.params.TestNet2Params;
import org.bitcoincashj.params.TestNet3Params;
import org.bitcoincashj.params.UnitTestParams;
import org.bitcoincashj.script.ScriptOpCodes;
import org.bitcoincashj.wallet.Wallet;
import org.bitcoincashj.wallet.Wallet.BalanceType;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import static org.bitcoincashj.core.Utils.HEX;
import static org.junit.Assert.*;

public class BlockTest {
    private static final NetworkParameters PARAMS = TestNet2Params.get();

    public static final byte[] blockBytes;

    static {
        // Block 00000000a6e5eb79dcec11897af55e90cd571a4335383a3ccfbc12ec81085935
        // One with lots of transactions in, so a good test of the merkle tree hashing.
        blockBytes = HEX.decode("0100000040f11b68435988807d64dff20261f7d9827825fbb37542601fb94d45000000000f28f7c69e2669981f92ff081c129e196200c60f4fad7911d93a682de0b49ea2ecd9d24c1844011d00d361050c01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07041844011d0142ffffffff0100f2052a01000000434104a313febd5f91b6a13bd9c5317030518fee96d1319a0eb10076917294933d09c17dc1588a06953a264738f2acea0c66b99e796caa4f28158e0dd5f6fed69a185bac000000000100000001aa18a952c3f73e5d7440bc570b2aa78f72059887b25b6a1790514b7feedec090000000008b483045022100a970ee6e96fa8bea1cf76d3bda3fb70441a6ec50014d4ea3adcdeae9fbfb5129022025ce9e090366dd6175071a0a5b4a4727571b9bd7bdd5a74d3d3bad7f63eb5dd4014104ac44bdf511477465cb70fef1d06b9241e74d26047ccbdfa641ec9a0115ad35594cbb58a61a6fd56893a405bcffbf6555995ddedc7e6cd4e5ceb83a37e1cf8f98ffffffff02004d92d86a0000001976a914b8083945473bc8289efb681f94de7b07a5b851ad88ac00743ba40b0000001976a914ef01911c9efec6799d1ee5f7c6fb072d9669da8088ac000000000100000001438bd97cb2172e0dd6f341e455e00b7d089747bd4e7f54bd802afe6a6d006c7c000000008a47304402207db94026c96572519101a08e2c864bbe51c987eda6266079a35286df68f123ca02202d7d24c616776a70cce6cb2f97a424e47c30d466e96b750ca03564810249073c014104880286646dab4c894a5ff1bf62bd80047a50b86446b326f2155de94a54d01f9058d4cbc7452563a7c18b2bfb353262fc5adac6307a9446e8c4669daa58e97071ffffffff0200743ba40b0000001976a914fce443c743b456606d1e70ff0d98c4609addc10688ac00ba1dd2050000001976a91411e3e67c08e5d791c97b3d49a8d52025d3f78d3a88ac000000000100000001dc4a6300b6eca8d7ab8e119e9fc4b18890c0e26ec950e681b8d5e46c214aee24010000008b48304502202bcf8632a11192f6b4998343c13589771e6715a080236087dcb1771cbab01809022100edcc38488dd70cd38c058994f143ca5d259071b8fe54c66bf67e55d4468dcacb01410475106e33e14e9cf35bc359dd4120b580ecf5412bb8803f2a927aecd4218d1346e242c7056dca2e4c114fcf2f60799bc5e79107bd1a8b8d5135c92f02bdb59834ffffffff0200f2052a010000001976a9146c9715e09fb00ba84af1ff916ff409b4a5dc9ae288ac00c817a8040000001976a914f7be161206700eb7be1bca5768232c61e4694f4788ac000000000100000001b6cc12ff76247895cb7a604d888012136f06bba64654262044ecb93ff7762c2f000000008b48304502206d795045622c7cdfb4a211c5b41d477920437c21e69214ab4a14f10fe0306b78022100840e55114d6922f3c5e44c7cdcf85dc800d1caef64e7846998423e4ba86714e6014104f88ae9067bc05136cb53a8c18f8549f544ff55ab87ada8f3ba7e2aea773ec73585b61f18ade1c0ddd6c447788578be5fb785c245a64d29b7ff5d28b85cbec58cffffffff0200743ba40b0000001976a914c8081083a8b741da2da260bc0656b88c7bfa6fbf88ac00743ba40b0000001976a914fce443c743b456606d1e70ff0d98c4609addc10688ac0000000001000000019a8d70c7a27560b28dfe778db9ce7f2ff235faf98d5123c07991682be90a4c16000000008b483045022100a118c34f63854ee03d15cca2918d592c295035c42e03be7b0c7e86e66d40ea790220558336d2583a1da00ed5bcad2de5d3b9d485431f702bf2f002267b35ab0b41a0014104f88ae9067bc05136cb53a8c18f8549f544ff55ab87ada8f3ba7e2aea773ec73585b61f18ade1c0ddd6c447788578be5fb785c245a64d29b7ff5d28b85cbec58cffffffff0200743ba40b0000001976a914a440ef00c2e1d39be93607da66568caa26e0501888ac00743ba40b0000001976a914e1d3e65f78f962c4e9dfd04db2119aeefa4e111088ac000000000100000001883acd4bff920f19c4e570e6b3e2d7503d1072d3ca098a124e23534ecdc879d5000000008a473044022040677305de69fd8c18e2c54d5b3c67c5c05735cf6b73d420ccd306762c4bfda2022032cd32ac15ac1820265ffce82654a6008cda22a79fb619ebb65e0af806e14f9b0141044423ef78a2859eb57c4a59dc0878141cf5a4b1fdef71d649d3fb5cf8ea6b1114f4086e5d684a0999d4435db99217a994cc3cf7ad435c8f4e44613d9d160916c4ffffffff0100743ba40b0000001976a914fce443c743b456606d1e70ff0d98c4609addc10688ac000000000100000001ceb27fb142ce3bf9a1f263653dc3971332c71dd10e0e83d647037f608c459f12000000008b4830450220389218287e87d0d7b7113eb20cc1cbf1a00d7acdca32bba7f184cd066db74d6a022100b0998058e5a242699a48f931004cf5550f4e8802b866ce1baf1a0b2616861f27014104255a048d416984101c17514a89289a7d5d3dc8c562850c7a3599f0c7c39bcf9c3a43df75e1e614e51d70c5f85212c99298a21f087be93ecba7ef3900d02c0e8bffffffff0200743ba40b0000001976a914211fd13b614521ed566ddd42738381e42c3c2b2088ac00d956345f0000001976a914d3cc345ba8bdf51d7097955f0f259731f4c34f4388ac000000000100000001703701493f08e82bf6d8cb7c517070eee9f62d14904e14636a7b4af4f34180c7010000008a4730440220061a61eae90ffcf13c10c88a88c085b02954f488823c2f5c81e83a5a833e9f3b02204a61498a9668b2793e77fe3b68585f2daff4dd5daf6097a82615035325ada4730141040db6308d6170333e2c50dee4c9f18f0ab84a7a5c4c88a6836a91f39cb8f4712e08bd72979c542d4b3b60e8dc2021c1b3cc45ffaa83f36a9dec3c4473ea2aa2f3ffffffff0200f2052a010000001976a9143e7e087b9b09149e0266b7a416da2709b4ccf58788ac00d6117e030000001976a914777af71a3b2a48e48f2e467f65028d85c1b5eb5288ac0000000001000000014bdc82abc7db9c06613a712e488685c6feb4522d25017b856222171c17d144e0000000008b4830450221009eb7edcbf8d6be63529264b07bb9f40cf1a0ca779235999e40f5311d70706f1102207f65c5f66982519e6d82e13ca3e61f4f071c73da6c5830b3c4461252012b474e0141045af9665878e6696fd069669951acc54a87c5e3b256a9e20cd8858e0dc5a8c53624e0c979096c00af8a8c60136eef9ffa3d511309417b8315b7f9e3e41e805e8fffffffff0100743ba40b0000001976a914e1d3e65f78f962c4e9dfd04db2119aeefa4e111088ac000000000100000001a854b2b84a76e43de59db647121cdfe481bd8ae9623a345c2188369775b533f7010000008c493046022100c4db6ecf679264c9b525628ec5a983710ff45a1d2d4aa0b54ee218ca9a1ad4df022100dc2e0077cfdd3cbeb28f7463632902ad5306f6d5c77c8149e5b9249bfea8060e014104f9a476b612bb9788c64b9b1e4c9d2deaae1ef0baf6eb593a95d00e2ef8a2beb897ea1fb7c3832e842dd6307fd162816c19c8f458fd8dae331dbc9062fb02e5d8ffffffff0200651b90530000001976a914d5c7c9aec292a807005f013c4d2122f7126e257788ac00743ba40b0000001976a914211fd13b614521ed566ddd42738381e42c3c2b2088ac0000000001000000012908482e9f7d31e9dd392bb6e788a329458a3bc95230b468e4b8c578d27a63b3000000008a4730440220549a7b422fc2020671acabfb937349bd87d985b2e4b9698e4ccacc985f61aee102204dc272322079e9114746db2f8d035d82b64523a69cd7be674173e063090cc8ac014104011a6c220a5549ff112c92c6c38dec93f66ef1f0a21d1409b92f0ccf0fb159aa8173a5b2413a45140fc02b45d63775bae03691d9dc87fd7a10d709a04922900cffffffff0200743ba40b0000001976a914211fd13b614521ed566ddd42738381e42c3c2b2088ac00f1dfeb470000001976a9140adcb4e90cc87f53d7618294222a8a4e193ae9f088ac00000000");
    }

    @Before
    public void setUp() throws Exception {
        Context context = new Context(PARAMS);
    }

    @Test
    public void testWork() throws Exception {
        BigInteger work = PARAMS.getGenesisBlock().getWork();
        // This number is printed by Bitcoin Core at startup as the calculated value of chainWork on testnet:
        //
        // SetBestChain: new best=00000007199508e34a9f  height=0  work=536879104
        assertEquals(BigInteger.valueOf(536879104L), work);
    }

    @Test
    public void testBlockVerification() throws Exception {
        Block block = PARAMS.getDefaultSerializer().makeBlock(blockBytes);
        block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
        assertEquals("00000000a6e5eb79dcec11897af55e90cd571a4335383a3ccfbc12ec81085935", block.getHashAsString());
    }
    
    @SuppressWarnings("deprecation")
    @Test
    public void testDate() throws Exception {
        Block block = PARAMS.getDefaultSerializer().makeBlock(blockBytes);
        assertEquals("4 Nov 2010 16:06:04 GMT", block.getTime().toGMTString());
    }

    @Test
    public void testProofOfWork() throws Exception {
        // This params accepts any difficulty target.
        NetworkParameters params = UnitTestParams.get();
        Block block = params.getDefaultSerializer().makeBlock(blockBytes);
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
        assertEquals(block.getNonce(), 2);
    }

    @Test
    public void testBadTransactions() throws Exception {
        Block block = PARAMS.getDefaultSerializer().makeBlock(blockBytes);
        // Re-arrange so the coinbase transaction is not first.
        Transaction tx1 = block.transactions.get(0);
        Transaction tx2 = block.transactions.get(1);
        block.transactions.set(0, tx2);
        block.transactions.set(1, tx1);
        try {
            block.verify(Block.BLOCK_HEIGHT_GENESIS, EnumSet.noneOf(Block.VerifyFlag.class));
            fail();
        } catch (VerificationException e) {
            // We should get here.
        }
    }

    @Test
    public void testHeaderParse() throws Exception {
        Block block = PARAMS.getDefaultSerializer().makeBlock(blockBytes);
        Block header = block.cloneAsHeader();
        Block reparsed = PARAMS.getDefaultSerializer().makeBlock(header.bitcoinSerialize());
        assertEquals(reparsed, header);
    }

    @Test
    public void testBitcoinSerialization() throws Exception {
        // We have to be able to reserialize everything exactly as we found it for hashing to work. This test also
        // proves that transaction serialization works, along with all its subobjects like scripts and in/outpoints.
        //
        // NB: This tests the bitcoin serialization protocol.
        Block block = PARAMS.getDefaultSerializer().makeBlock(blockBytes);
        assertTrue(Arrays.equals(blockBytes, block.bitcoinSerialize()));
    }
    
    @Test
    public void testUpdateLength() {
        NetworkParameters params = UnitTestParams.get();
        Block block = params.getGenesisBlock().createNextBlockWithCoinbase(Block.BLOCK_VERSION_GENESIS, new ECKey().getPubKey(), Block.BLOCK_HEIGHT_GENESIS);
        assertEquals(block.bitcoinSerialize().length, block.length);
        final int origBlockLen = block.length;
        Transaction tx = new Transaction(params);
        // this is broken until the transaction has > 1 input + output (which is required anyway...)
        //assertTrue(tx.length == tx.bitcoinSerialize().length && tx.length == 8);
        byte[] outputScript = new byte[10];
        Arrays.fill(outputScript, (byte) ScriptOpCodes.OP_FALSE);
        tx.addOutput(new TransactionOutput(params, null, Coin.SATOSHI, outputScript));
        tx.addInput(new TransactionInput(params, null, new byte[] {(byte) ScriptOpCodes.OP_FALSE},
                new TransactionOutPoint(params, 0, Sha256Hash.of(new byte[] { 1 }))));
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
        block.getTransactions().get(1).addInput(new TransactionInput(params, null, new byte[] {(byte) ScriptOpCodes.OP_FALSE},
                new TransactionOutPoint(params, 0, Sha256Hash.of(new byte[] { 1 }))));
        assertEquals(block.length, origBlockLen + tx.length);
        assertEquals(tx.length, origTxLength + 41); // - 1 + 40 + 1 + 1
    }

    @Test
    public void testCoinbaseHeightTestnet() throws Exception {
        // Testnet block 21066 (hash 0000000004053156021d8e42459d284220a7f6e087bf78f30179c3703ca4eefa)
        // contains a coinbase transaction whose height is two bytes, which is
        // shorter than we see in most other cases.

        Block block = TestNet3Params.get().getDefaultSerializer().makeBlock(
            ByteStreams.toByteArray(getClass().getResourceAsStream("block_testnet21066.dat")));

        // Check block.
        assertEquals("0000000004053156021d8e42459d284220a7f6e087bf78f30179c3703ca4eefa", block.getHashAsString());
        block.verify(21066, EnumSet.of(Block.VerifyFlag.HEIGHT_IN_COINBASE));

        // Testnet block 32768 (hash 000000007590ba495b58338a5806c2b6f10af921a70dbd814e0da3c6957c0c03)
        // contains a coinbase transaction whose height is three bytes, but could
        // fit in two bytes. This test primarily ensures script encoding checks
        // are applied correctly.

        block = TestNet3Params.get().getDefaultSerializer().makeBlock(
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
        final NetworkParameters PARAMS = MainNetParams.get();

        Block block169482 = PARAMS.getDefaultSerializer().makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block169482.dat")));

        // Check block.
        assertNotNull(block169482);
        block169482.verify(169482, EnumSet.noneOf(Block.VerifyFlag.class));
        assertEquals(BLOCK_NONCE, block169482.getNonce());

        StoredBlock storedBlock = new StoredBlock(block169482, BigInteger.ONE, 169482); // Nonsense work - not used in test.

        // Create a wallet contain the miner's key that receives a spend from a coinbase.
        ECKey miningKey = DumpedPrivateKey.fromBase58(PARAMS, MINING_PRIVATE_KEY).getKey();
        assertNotNull(miningKey);
        Context context = new Context(PARAMS);
        Wallet wallet = new Wallet(context);
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
    public void isBIPs() throws Exception {
        final MainNetParams mainnet = MainNetParams.get();
        final Block genesis = mainnet.getGenesisBlock();
        assertFalse(genesis.isBIP34());
        assertFalse(genesis.isBIP66());
        assertFalse(genesis.isBIP65());

        // 227835/00000000000001aa077d7aa84c532a4d69bdbff519609d1da0835261b7a74eb6: last version 1 block
        final Block block227835 = mainnet.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227835.dat")));
        assertFalse(block227835.isBIP34());
        assertFalse(block227835.isBIP66());
        assertFalse(block227835.isBIP65());

        // 227836/00000000000000d0dfd4c9d588d325dce4f32c1b31b7c0064cba7025a9b9adcc: version 2 block
        final Block block227836 = mainnet.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block227836.dat")));
        assertTrue(block227836.isBIP34());
        assertFalse(block227836.isBIP66());
        assertFalse(block227836.isBIP65());

        // 363703/0000000000000000011b2a4cb91b63886ffe0d2263fd17ac5a9b902a219e0a14: version 3 block
        final Block block363703 = mainnet.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block363703.dat")));
        assertTrue(block363703.isBIP34());
        assertTrue(block363703.isBIP66());
        assertFalse(block363703.isBIP65());

        // 383616/00000000000000000aab6a2b34e979b09ca185584bd1aecf204f24d150ff55e9: version 4 block
        final Block block383616 = mainnet.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block383616.dat")));
        assertTrue(block383616.isBIP34());
        assertTrue(block383616.isBIP66());
        assertTrue(block383616.isBIP65());

        // 370661/00000000000000001416a613602d73bbe5c79170fd8f39d509896b829cf9021e: voted for BIP101
        final Block block370661 = mainnet.getDefaultSerializer()
                .makeBlock(ByteStreams.toByteArray(getClass().getResourceAsStream("block370661.dat")));
        assertTrue(block370661.isBIP34());
        assertTrue(block370661.isBIP66());
        assertTrue(block370661.isBIP65());
    }
}
