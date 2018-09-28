package org.bitcoinj.core;

import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import static org.junit.Assert.*;

public class BlockGoldTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    @Test
    public void serializeBlockGold_afterEquihashFork_Testnet() throws Exception {
        // Arrange
        String hex = "000000202ee33f8434abb3b5874360c8ff21ae6095333440809cdbd258ef18cd0ec60200f30faecfb730de167ab9205b9445d311626294bd357af08952f758011e912b0978390000000000000000000000000000000000000000000000000000000000006c652a5b6e12031f3dcbc9e40000501d5d4e0b000000000000000000000000000000000000000000641773e3fe8df4c994e84cc9bfe182e60cbab992ac1f9dba6ba33560b2cc60df6b2daa3f4eaf23aa596d4adea5343ca57007701ce77910dca21afbb6bf0c1be3b569536aa9217980b6eb1b235277b068c906a3b01e9fb5ce66c7533be7ccb62401c7a8425b03010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff31027839005a2d4e4f4d50212068747470733a2f2f6769746875622e636f6d2f6a6f7368756179616275742f7a2d6e6f6d70ffffffff0399a80b27010000001976a91452d96e6fd448b7854be4ad7b0951f1aeab35aa7688ac30f2fa02000000001976a9141e0c9f2699c061035de67d3c69a4ec4726bbe07988ac0000000000000000266a24aa21a9ed3c17c4e849d18076a6c4d84b5c24341b13d083f7b544a86de1bae069ea4d9a900120000000000000000000000000000000000000000000000000000000000000000000000000020000000222c160cb5fb7ff13351da2fdb9df4dc4fb85622156bc0d5fbfda3dca772eba6b000000006b483045022100b9b9476eb9253e7e016fa77d18e1d60564463dfc7bc50dfc71dd4a549d2dd53b0220302f6ef43ed4deb8fa905285ad4d55e01c9fe933ce666fd41e4651b0cb45ef1a4121021460a24384bbfac33bad5aaebf3f4d8c0a74d199fad5bb834e2acd1de31fd82afeffffffe7488c66c838957efad91c9b6ac558afe995a9e1b1efe56d8cbe19151f6fd183000000006b483045022100d422a335b2c39ca62f9df7bae5b863ee171db6f4227701a6ff4e56a644ef3d4002207e0dda190600f6ce63273a8681fd31480acc35e3f598b4f572ffa8be8dfefdca412103794652f84e69c9a4bc3cf9ee8659cd0d8ac1dd40c08cf5557837937e8d6336c6feffffff0248991600000000001976a91476ff4067bce12065d2d5a558b78d76f63e83d56888acc0590b27010000001976a9144dcdfa27f55c2ea07d01b3495a01391d42f60c9d88ac773900000200000002a53b252e65fd1433ca241d03250c38b308c541996128a3ccc7cc872355996f50000000006b483045022100b3e755a89b824561f9e387a5f184b157511a75a22453323b7e5622ba6c94e8ba022001ef2a1b66602548f8a8a43b6d89620e6a35bbb21c373e82f2de628716a522d1412103cebe8dcff2e107ff16267dd3074a792b300700e5008e441790e39a0428f08317feffffffdd1179179496b1aaecc30a75878a6fa6b1b338eaea23b4688c2f538c16f4a6ca010000006b4830450221008a25e84d42d4c2d3e226e16cf4149ac76f85d2181ccc07a6814e311d3e1a4e330220718264bbaccce910d9643a34110b19fdfe2e952ed2622fd02fc85f0366f04a4d412102d62958f9f264ff99460908a57b07a6a9ae1187e0848925c081b3ba2bceeaf59efeffffff028cff0a27010000001976a9145801335042eed7b156235017e3408f550f233a3888acfe3a9600000000001976a914c3fcc544d7cae7a954a044b5e559e17a3c156f2688ac77390000";
        byte[] bytes = DatatypeConverter.parseHexBinary(hex);

        // Act
        BitcoinSerializer serializer = new BitcoinGoldSerializer(TESTNET, false);
        Block block = TESTNET.getBitcoinGoldSerializer().makeBlock(bytes);

        // Assert
        assertEquals(536870912, block.getVersion());
        assertEquals("0002c60ecd18ef58d2db9c804034339560ae21ffc8604387b5b3ab34843fe32e", block.getPrevBlockHash().toString());
        assertEquals("092b911e0158f75289f07a35bd94626211d345945b20b97a16de30b7cfae0ff3", block.getMerkleRoot().toString());
        assertEquals(14712, block.getHeight());
        assertEquals(1529505132, block.getTimeSeconds());
        assertEquals("1f03126e",  Long.toHexString(block.getDifficultyTarget()));
        assertEquals("0000000000000000000000000000000000000000000b4e5d1d500000e4c9cb3d", block.getNonceBytesHex());
        String solution = "1773e3fe8df4c994e84cc9bfe182e60cbab992ac1f9dba6ba33560b2cc60df6b2daa3f4eaf23aa596d4adea5343ca57007701ce77910dca21afbb6bf0c1be3b569536aa9217980b6eb1b235277b068c906a3b01e9fb5ce66c7533be7ccb62401c7a8425b";
        assertEquals(solution, block.getSolutionHex());
        assertEquals(3, block.transactions.size());
        assertEquals("598604a48bcf5e7efb40b18a3b21fcd1bfdfb4862b621fb75533f108bafc8b32", block.transactions.get(0).getHashAsString());
        assertEquals("586e0a902d1fe8ee7eb714e0ab0a4eb4b09591a6b07fec237ac68bd959d752b9", block.transactions.get(1).getHashAsString());
        assertEquals("c8f95620d0b8244048c575c10ba9b1375e515e193d08a4debb8a9e1015167bd3", block.transactions.get(2).getHashAsString());
    }
}