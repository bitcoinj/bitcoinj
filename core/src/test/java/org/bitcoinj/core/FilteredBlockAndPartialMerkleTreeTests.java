/**
 * Copyright 2012 Matt Corallo
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

import com.google.common.collect.*;
import org.bitcoinj.core.TransactionConfidence.*;
import org.bitcoinj.store.*;
import org.bitcoinj.testing.*;
import org.bitcoinj.wallet.*;
import org.junit.*;
import org.junit.runner.*;
import org.junit.runners.*;

import java.math.*;
import java.util.*;

import static org.bitcoinj.core.Utils.*;
import static org.junit.Assert.*;

@RunWith(value = Parameterized.class)
public class FilteredBlockAndPartialMerkleTreeTests extends TestWithPeerGroup {
    @Parameterized.Parameters
    public static Collection<ClientType[]> parameters() {
        return Arrays.asList(new ClientType[] {ClientType.NIO_CLIENT_MANAGER},
                             new ClientType[] {ClientType.BLOCKING_CLIENT_MANAGER});
    }

    public FilteredBlockAndPartialMerkleTreeTests(ClientType clientType) {
        super(clientType);
    }

    @Before
    public void setUp() throws Exception {
        context = new Context(params);
        MemoryBlockStore store = new MemoryBlockStore(params);

        // Cheat and place the previous block (block 100000) at the head of the block store without supporting blocks
        store.put(new StoredBlock(new Block(params, HEX.decode("0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710")),
                BigInteger.valueOf(1), 100000));
        store.setChainHead(store.get(new Sha256Hash("000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506")));

        KeyChainGroup group = new KeyChainGroup(params);
        group.importKeys(ECKey.fromPublicOnly(HEX.decode("04b27f7e9475ccf5d9a431cb86d665b8302c140144ec2397fce792f4a4e7765fecf8128534eaa71df04f93c74676ae8279195128a1506ebf7379d23dab8fca0f63")),
                ECKey.fromPublicOnly(HEX.decode("04732012cb962afa90d31b25d8fb0e32c94e513ab7a17805c14ca4c3423e18b4fb5d0e676841733cb83abaf975845c9f6f2a8097b7d04f4908b18368d6fc2d68ec")),
                ECKey.fromPublicOnly(HEX.decode("04cfb4113b3387637131ebec76871fd2760fc430dd16de0110f0eb07bb31ffac85e2607c189cb8582ea1ccaeb64ffd655409106589778f3000fdfe3263440b0350")),
                ECKey.fromPublicOnly(HEX.decode("04b2f30018908a59e829c1534bfa5010d7ef7f79994159bba0f534d863ef9e4e973af6a8de20dc41dbea50bc622263ec8a770b2c9406599d39e4c9afe61f8b1613")));
        wallet = new Wallet(params, group);

        super.setUp(store);
    }

    @After
    public void tearDown() {
        super.tearDown();
    }

    @Test
    public void deserializeFilteredBlock() throws Exception {
        // Random real block (000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45)
        // With one tx
        FilteredBlock block = new FilteredBlock(params, HEX.decode("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101"));
        
        // Check that the header was properly deserialized
        assertTrue(block.getBlockHeader().getHash().equals(new Sha256Hash("000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45")));
        
        // Check that the partial merkle tree is correct
        List<Sha256Hash> txesMatched = block.getTransactionHashes();
        assertTrue(txesMatched.size() == 1);
        assertTrue(txesMatched.contains(new Sha256Hash("63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5")));

        // Check round tripping.
        assertEquals(block, new FilteredBlock(params, block.bitcoinSerialize()));
    }

    @Test
    public void createFilteredBlock() throws Exception {
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();
        Transaction tx1 = FakeTxBuilder.createFakeTx(params, Coin.COIN,  key1);
        Transaction tx2 = FakeTxBuilder.createFakeTx(params, Coin.FIFTY_COINS, key2.toAddress(params));
        Block block = FakeTxBuilder.makeSolvedTestBlock(params.getGenesisBlock(), new Address(params, "msg2t2V2sWNd85LccoddtWysBTR8oPnkzW"), tx1, tx2);
        BloomFilter filter = new BloomFilter(4, 0.1, 1);
        filter.insert(key1);
        filter.insert(key2);
        FilteredBlock filteredBlock = filter.applyAndUpdate(block);
        assertEquals(4, filteredBlock.getTransactionCount());
        // This call triggers verification of the just created data.
        List<Sha256Hash> txns = filteredBlock.getTransactionHashes();
        assertTrue(txns.contains(tx1.getHash()));
        assertTrue(txns.contains(tx2.getHash()));
    }

    private Sha256Hash numAsHash(int num) {
        byte[] bits = new byte[32];
        bits[0] = (byte) num;
        return new Sha256Hash(bits);
    }

    @Test(expected = VerificationException.class)
    public void merkleTreeMalleability() throws Exception {
        List<Sha256Hash> hashes = Lists.newArrayList();
        for (byte i = 1; i <= 10; i++) hashes.add(numAsHash(i));
        hashes.add(numAsHash(9));
        hashes.add(numAsHash(10));
        byte[] includeBits = new byte[2];
        Utils.setBitLE(includeBits, 9);
        Utils.setBitLE(includeBits, 10);
        PartialMerkleTree pmt = PartialMerkleTree.buildFromLeaves(params, includeBits, hashes);
        List<Sha256Hash> matchedHashes = Lists.newArrayList();
        pmt.getTxnHashAndMerkleRoot(matchedHashes);
    }

    @Test
    public void serializeDownloadBlockWithWallet() throws Exception {
        // First we create all the neccessary objects, including lots of serialization and double-checks
        // Note that all serialized forms here are generated by the reference client/pulled from block explorer
        Block block = new Block(params, HEX.decode("0100000006e533fd1ada86391f3f6c343204b0d278d4aaec1c0b20aa27ba0300000000006abbb3eb3d733a9fe18967fd7d4c117e4ccbbac5bec4d910d900b3ae0793e77f54241b4d4c86041b4089cc9b0c01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b010dffffffff0100f2052a01000000434104b27f7e9475ccf5d9a431cb86d665b8302c140144ec2397fce792f4a4e7765fecf8128534eaa71df04f93c74676ae8279195128a1506ebf7379d23dab8fca0f63ac000000000100000001d992e5a888a86d4c7a6a69167a4728ee69497509740fc5f456a24528c340219a000000008b483045022100f0519bdc9282ff476da1323b8ef7ffe33f495c1a8d52cc522b437022d83f6a230220159b61d197fbae01b4a66622a23bc3f1def65d5fa24efd5c26fa872f3a246b8e014104839f9023296a1fabb133140128ca2709f6818c7d099491690bd8ac0fd55279def6a2ceb6ab7b5e4a71889b6e739f09509565eec789e86886f6f936fa42097adeffffffff02000fe208010000001976a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac00e32321000000001976a9140c34f4e29ab5a615d5ea28d4817f12b137d62ed588ac0000000001000000059daf0abe7a92618546a9dbcfd65869b6178c66ec21ccfda878c1175979cfd9ef000000004a493046022100c2f7f25be5de6ce88ac3c1a519514379e91f39b31ddff279a3db0b1a229b708b022100b29efbdbd9837cc6a6c7318aa4900ed7e4d65662c34d1622a2035a3a5534a99a01ffffffffd516330ebdf075948da56db13d22632a4fb941122df2884397dda45d451acefb0000000048473044022051243debe6d4f2b433bee0cee78c5c4073ead0e3bde54296dbed6176e128659c022044417bfe16f44eb7b6eb0cdf077b9ce972a332e15395c09ca5e4f602958d266101ffffffffe1f5aa33961227b3c344e57179417ce01b7ccd421117fe2336289b70489883f900000000484730440220593252bb992ce3c85baf28d6e3aa32065816271d2c822398fe7ee28a856bc943022066d429dd5025d3c86fd8fd8a58e183a844bd94aa312cefe00388f57c85b0ca3201ffffffffe207e83718129505e6a7484831442f668164ae659fddb82e9e5421a081fb90d50000000049483045022067cf27eb733e5bcae412a586b25a74417c237161a084167c2a0b439abfebdcb2022100efcc6baa6824b4c5205aa967e0b76d31abf89e738d4b6b014e788c9a8cccaf0c01ffffffffe23b8d9d80a9e9d977fab3c94dbe37befee63822443c3ec5ae5a713ede66c3940000000049483045022020f2eb35036666b1debe0d1d2e77a36d5d9c4e96c1dba23f5100f193dbf524790221008ce79bc1321fb4357c6daee818038d41544749127751726e46b2b320c8b565a201ffffffff0200ba1dd2050000001976a914366a27645806e817a6cd40bc869bdad92fe5509188ac40420f00000000001976a914ee8bd501094a7d5ca318da2506de35e1cb025ddc88ac0000000001000000010abad2dc0c9b4b1dbb023077da513f81e5a71788d8680fca98ef1c37356c459c000000004a493046022100a894e521c87b3dbe23007079db4ac2896e9e791f8b57317ba6c0d99a7becd27a022100bc40981393eafeb33e89079f857c728701a9af4523c3f857cd96a500f240780901ffffffff024026ee22010000001976a914d28f9cefb58c1f7a5f97aa6b79047585f58fbd4388acc0cb1707000000001976a9142229481696e417aa5f51ad751d8cd4c6a669e4fe88ac000000000100000001f66d89b3649e0b18d84db056930676cb81c0168042fc4324c3682e252ea9410d0000000048473044022038e0b55b37c9253bfeda59c76c0134530f91fb586d6eb21738a77a984f370a44022048d4d477aaf97ef9c8275bbc5cb19b9c8a0e9b1f9fdafdd39bc85bf6c2f04a4d01ffffffff024041a523010000001976a914955f70ac8792b48b7bd52b15413bd8500ecf32c888ac00f36f06000000001976a91486116d15f3dbb23a2b58346f36e6ec2d867eba2b88ac00000000010000000126c384984f63446a4f2be8dd6531ba9837bd5f2c3d37403c5f51fb9192ee754e010000008b48304502210083af8324456f052ff1b2597ff0e6a8cce8b006e379a410cf781be7874a2691c2022072259e2f7292960dea0ffc361bbad0b861f719beb8550476f22ce0f82c023449014104f3ed46a81cba02af0593e8572a9130adb0d348b538c829ccaaf8e6075b78439b2746a76891ce7ba71abbcbb7ca76e8a220782738a6789562827c1065b0ce911dffffffff02c0dd9107000000001976a91463d4dd1b29d95ed601512b487bfc1c49d84d057988ac00a0491a010000001976a91465746bef92511df7b34abf71c162efb7ae353de388ac0000000001000000011b56cf3aab3286d582c055a42af3a911ee08423f276da702bb67f1222ac1a5b6000000008c4930460221009e9fba682e162c9627b96b7df272006a727988680b956c61baff869f0907b8fb022100a9c19adc7c36144bafe526630783845e5cb9554d30d3edfb56f0740274d507f30141046e0efbfac7b1615ad553a6f097615bc63b7cdb3b8e1cb3263b619ba63740012f51c7c5b09390e3577e377b7537e61226e315f95f926444fc5e5f2978c112e448ffffffff02c0072b11010000001976a914b73e9e01933351ca076faf8e0d94dd58079d0b1f88ac80b63908000000001976a9141aca0bdf0d2cee63db19aa4a484f45a4e26a880c88ac000000000100000001251b187504ea873b2c3915fad401f7a7734cc13567e0417708e86294a29f4f68010000008b4830450221009bef423141ed1ae60d0a5bcaa57b1673fc96001f0d4e105535cca817ba5a7724022037c399bd30374f22481ffc81327cfca4951c7264b227f765fcd6a429f3d9d2080141044d0d1b4f194c31a73dbce41c42b4b3946849117c5bb320467e014bad3b1532f28a9a1568ba7108f188e7823b6e618e91d974306701379a27b9339e646e156e7bffffffff02c00fd103010000001976a914ef7f5d9e1bc6ed68cfe0b1db9d8f09cef0f3ba4a88ac004dd208000000001976a914c22420641cea028c9e06c4d9104c1646f8b1769088ac0000000001000000013486dd5f0a2f3efcc04f64cb03872c021f98ee39f514747ce5336b874bbe47a7010000008b48304502201cadddc2838598fee7dc35a12b340c6bde8b389f7bfd19a1252a17c4b5ed2d71022100c1a251bbecb14b058a8bd77f65de87e51c47e95904f4c0e9d52eddc21c1415ac014104fe7df86d58aafa9246ca6fd30c905714533c25f700e2329b8ecec8aa52083b844baa3a8acd5d6b9732dcb39079bb56ba2711a3580dec824955fce0596a460c11ffffffff02c011f6e1000000001976a91490fac83c9adde91d670dde8755f8b475ab9e427d88acc0f9df15000000001976a91437f691b3e8ee5dcb56c2e31af4c80caa2df3b09b88ac00000000010000000170016bd1274b795b262f32a53003a4714b22b62f9057adf5fbe6ed939003b5190100000089463043022061456499582170a94d6b54308f792e37dad28bf0ed7aa61021f0301d2774d378021f4224b33f707efd810a01dd34ea86d6069cd599cc435513a0eef8c83c137bf7014104a2c95d6b98e745448eb45ed0ba95cf24dd7c3b16386e1028e24a0358ee4afc33e2f0199139853edaf32845d8a42254c75f7dc8add3286c682c650fbd93f0a4a1ffffffff02001bd2b7000000001976a9141b11c6acaa5223013f3a3240fdb024ecd9f8135488ac8023ad18000000001976a914ada27ca87bbaa1ee6fb1cb61bb0a29baaf6da2c988ac000000000100000001c8ff91f031ec6a5aba4baee6549e61dd01f26f61b70e2f1574f24cd680f464ad000000008b48304502210082235e21a2300022738dabb8e1bbd9d19cfb1e7ab8c30a23b0afbb8d178abcf3022024bf68e256c534ddfaf966bf908deb944305596f7bdcc38d69acad7f9c868724014104174f9eef1157dc1ad5eac198250b70d1c3b04b2fca12ad1483f07358486f02909b088bbc83f4de55f767f6cdf9d424aa02b5eeaffa08394d39b717895fc08d0affffffff0200ea3b43000000001976a914fb32df708f0610901f6d1b6df8c9c368fe0d981c88ac800f1777000000001976a914462c501c70fb996d15ac0771e7fc8d3ca3f7201888ac000000000100000001c67323867de802402e780a70e0deba3c708c4d87497e17590afee9c321f1c680010000008a473044022042734b25f54845d662e6499b75ff8529ff47f42fd224498a9f752d212326dbfa0220523e4b7b570bbb1f3af02baa2c04ea8eb7b0fccb1522cced130b666ae9a9d014014104b5a23b922949877e9eaf7512897ed091958e2e8cf05b0d0eb9064e7976043fde6023b4e2c188b7e38ef94eec6845dc4933f5e8635f1f6a3702290956aa9e284bffffffff0280041838030000001976a91436e5884215f7d3044be5d37bdd8c987d9d942c8488ac404b4c00000000001976a91460085d6838f8a44a21a0de56ff963cfa6242a96188ac00000000"));
        FilteredBlock filteredBlock = new FilteredBlock(params, HEX.decode("0100000006e533fd1ada86391f3f6c343204b0d278d4aaec1c0b20aa27ba0300000000006abbb3eb3d733a9fe18967fd7d4c117e4ccbbac5bec4d910d900b3ae0793e77f54241b4d4c86041b4089cc9b0c000000084c30b63cfcdc2d35e3329421b9805ef0c6565d35381ca857762ea0b3a5a128bbca5065ff9617cbcba45eb23726df6498a9b9cafed4f54cbab9d227b0035ddefbbb15ac1d57d0182aaee61c74743a9c4f785895e563909bafec45c9a2b0ff3181d77706be8b1dcc91112eada86d424e2d0a8907c3488b6e44fda5a74a25cbc7d6bb4fa04245f4ac8a1a571d5537eac24adca1454d65eda446055479af6c6d4dd3c9ab658448c10b6921b7a4ce3021eb22ed6bb6a7fde1e5bcc4b1db6615c6abc5ca042127bfaf9f44ebce29cb29c6df9d05b47f35b2edff4f0064b578ab741fa78276222651209fe1a2c4c0fa1c58510aec8b090dd1eb1f82f9d261b8273b525b02ff1a"));
        
        // Block 100001
        assertTrue(block.getHash().equals(new Sha256Hash("00000000000080b66c911bd5ba14a74260057311eaeb1982802f7010f1a9f090")));
        assertTrue(filteredBlock.getHash().equals(block.getHash()));
        
        List<Sha256Hash> txHashList = filteredBlock.getTransactionHashes();
        assertTrue(txHashList.size() == 4);
        // Four transactions (0, 1, 2, 6) from block 100001
        Transaction tx0 = new Transaction(params, HEX.decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b010dffffffff0100f2052a01000000434104b27f7e9475ccf5d9a431cb86d665b8302c140144ec2397fce792f4a4e7765fecf8128534eaa71df04f93c74676ae8279195128a1506ebf7379d23dab8fca0f63ac00000000"));
        assertTrue(tx0.getHash().equals(new Sha256Hash("bb28a1a5b3a02e7657a81c38355d56c6f05e80b9219432e3352ddcfc3cb6304c")));
        assertEquals(tx0.getHash(), txHashList.get(0));
        
        Transaction tx1 = new Transaction(params, HEX.decode("0100000001d992e5a888a86d4c7a6a69167a4728ee69497509740fc5f456a24528c340219a000000008b483045022100f0519bdc9282ff476da1323b8ef7ffe33f495c1a8d52cc522b437022d83f6a230220159b61d197fbae01b4a66622a23bc3f1def65d5fa24efd5c26fa872f3a246b8e014104839f9023296a1fabb133140128ca2709f6818c7d099491690bd8ac0fd55279def6a2ceb6ab7b5e4a71889b6e739f09509565eec789e86886f6f936fa42097adeffffffff02000fe208010000001976a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac00e32321000000001976a9140c34f4e29ab5a615d5ea28d4817f12b137d62ed588ac00000000"));
        assertTrue(tx1.getHash().equals(new Sha256Hash("fbde5d03b027d2b9ba4cf5d4fecab9a99864df2637b25ea4cbcb1796ff6550ca")));
        assertEquals(tx1.getHash(), txHashList.get(1));

        Transaction tx2 = new Transaction(params, HEX.decode("01000000059daf0abe7a92618546a9dbcfd65869b6178c66ec21ccfda878c1175979cfd9ef000000004a493046022100c2f7f25be5de6ce88ac3c1a519514379e91f39b31ddff279a3db0b1a229b708b022100b29efbdbd9837cc6a6c7318aa4900ed7e4d65662c34d1622a2035a3a5534a99a01ffffffffd516330ebdf075948da56db13d22632a4fb941122df2884397dda45d451acefb0000000048473044022051243debe6d4f2b433bee0cee78c5c4073ead0e3bde54296dbed6176e128659c022044417bfe16f44eb7b6eb0cdf077b9ce972a332e15395c09ca5e4f602958d266101ffffffffe1f5aa33961227b3c344e57179417ce01b7ccd421117fe2336289b70489883f900000000484730440220593252bb992ce3c85baf28d6e3aa32065816271d2c822398fe7ee28a856bc943022066d429dd5025d3c86fd8fd8a58e183a844bd94aa312cefe00388f57c85b0ca3201ffffffffe207e83718129505e6a7484831442f668164ae659fddb82e9e5421a081fb90d50000000049483045022067cf27eb733e5bcae412a586b25a74417c237161a084167c2a0b439abfebdcb2022100efcc6baa6824b4c5205aa967e0b76d31abf89e738d4b6b014e788c9a8cccaf0c01ffffffffe23b8d9d80a9e9d977fab3c94dbe37befee63822443c3ec5ae5a713ede66c3940000000049483045022020f2eb35036666b1debe0d1d2e77a36d5d9c4e96c1dba23f5100f193dbf524790221008ce79bc1321fb4357c6daee818038d41544749127751726e46b2b320c8b565a201ffffffff0200ba1dd2050000001976a914366a27645806e817a6cd40bc869bdad92fe5509188ac40420f00000000001976a914ee8bd501094a7d5ca318da2506de35e1cb025ddc88ac00000000"));
        assertTrue(tx2.getHash().equals(new Sha256Hash("8131ffb0a2c945ecaf9b9063e59558784f9c3a74741ce6ae2a18d0571dac15bb")));
        assertEquals(tx2.getHash(), txHashList.get(2));


        Transaction tx3 = new Transaction(params, HEX.decode("01000000011b56cf3aab3286d582c055a42af3a911ee08423f276da702bb67f1222ac1a5b6000000008c4930460221009e9fba682e162c9627b96b7df272006a727988680b956c61baff869f0907b8fb022100a9c19adc7c36144bafe526630783845e5cb9554d30d3edfb56f0740274d507f30141046e0efbfac7b1615ad553a6f097615bc63b7cdb3b8e1cb3263b619ba63740012f51c7c5b09390e3577e377b7537e61226e315f95f926444fc5e5f2978c112e448ffffffff02c0072b11010000001976a914b73e9e01933351ca076faf8e0d94dd58079d0b1f88ac80b63908000000001976a9141aca0bdf0d2cee63db19aa4a484f45a4e26a880c88ac00000000"));
        assertTrue(tx3.getHash().equals(new Sha256Hash("c5abc61566dbb1c4bce5e1fda7b66bed22eb2130cea4b721690bc1488465abc9")));
        assertEquals(tx3.getHash(),txHashList.get(3));

        BloomFilter filter = wallet.getBloomFilter(wallet.getKeychainSize()*2, 0.001, 0xDEADBEEF);
        // Compare the serialized bloom filter to a known-good value
        assertArrayEquals(filter.bitcoinSerialize(), HEX.decode("0e1b091ca195e45a9164889b6bc46a09000000efbeadde02"));

        // Create a peer.
        peerGroup.start();
        InboundMessageQueuer p1 = connectPeer(1);
        assertEquals(1, peerGroup.numConnectedPeers());
        // Send an inv for block 100001
        InventoryMessage inv = new InventoryMessage(params);
        inv.addBlock(block);
        inbound(p1, inv);
        
        // Check that we properly requested the correct FilteredBlock
        Object getData = outbound(p1);
        assertTrue(getData instanceof GetDataMessage);
        assertTrue(((GetDataMessage)getData).getItems().size() == 1);
        assertTrue(((GetDataMessage)getData).getItems().get(0).hash.equals(block.getHash()));
        assertTrue(((GetDataMessage)getData).getItems().get(0).type == InventoryItem.Type.FilteredBlock);
        
        // Check that we then immediately pinged.
        Object ping = outbound(p1);
        assertTrue(ping instanceof Ping);
        
        // Respond with transactions and the filtered block
        inbound(p1, filteredBlock);
        inbound(p1, tx0);
        inbound(p1, tx1);
        inbound(p1, tx2);
        inbound(p1, tx3);
        inbound(p1, new Pong(((Ping)ping).getNonce()));

        pingAndWait(p1);

        Set<Transaction> transactions = wallet.getTransactions(false);
        assertTrue(transactions.size() == 4);
        for (Transaction tx : transactions) {
            assertTrue(tx.getConfidence().getConfidenceType() == ConfidenceType.BUILDING);
            assertTrue(tx.getConfidence().getDepthInBlocks() == 1);
            assertTrue(tx.getAppearsInHashes().keySet().contains(block.getHash()));
            assertTrue(tx.getAppearsInHashes().size() == 1);
        }

        // Peer 1 goes away.
        closePeer(peerOf(p1));
    }
}
