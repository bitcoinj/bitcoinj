/*
 * Copyright 2014 Google Inc.
 * Copyright 2016 Andreas Schildbach
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

import org.bitcoinj.core.TransactionConfidence.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.*;
import org.bitcoinj.script.*;
import org.bitcoinj.testing.*;
import org.easymock.*;
import org.junit.*;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.*;
import static org.bitcoinj.core.Utils.HEX;

import static org.bitcoinj.core.Utils.uint32ToByteStreamLE;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Just check the Transaction.verify() method. Most methods that have complicated logic in Transaction are tested
 * elsewhere, e.g. signing and hashing are well exercised by the wallet tests, the full block chain tests and so on.
 * The verify method is also exercised by the full block chain tests, but it can also be used by API users alone,
 * so we make sure to cover it here as well.
 */
public class TransactionTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final Address ADDRESS = LegacyAddress.fromKey(UNITTEST, new ECKey());

    private Transaction tx;

    @Before
    public void setUp() throws Exception {
        Context context = new Context(UNITTEST);
        tx = FakeTxBuilder.createFakeTx(UNITTEST);
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyOutputs() throws Exception {
        tx.clearOutputs();
        tx.verify();
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyInputs() throws Exception {
        tx.clearInputs();
        tx.verify();
    }

    @Test(expected = VerificationException.LargerThanMaxBlockSize.class)
    public void tooHuge() throws Exception {
        tx.getInput(0).setScriptBytes(new byte[Block.MAX_BLOCK_SIZE]);
        tx.verify();
    }

    @Test(expected = VerificationException.DuplicatedOutPoint.class)
    public void duplicateOutPoint() throws Exception {
        TransactionInput input = tx.getInput(0);
        input.setScriptBytes(new byte[1]);
        tx.addInput(input.duplicateDetached());
        tx.verify();
    }

    @Test(expected = VerificationException.NegativeValueOutput.class)
    public void negativeOutput() throws Exception {
        tx.getOutput(0).setValue(Coin.NEGATIVE_SATOSHI);
        tx.verify();
    }

    @Test(expected = VerificationException.ExcessiveValue.class)
    public void exceedsMaxMoney2() throws Exception {
        Coin half = UNITTEST.getMaxMoney().divide(2).add(Coin.SATOSHI);
        tx.getOutput(0).setValue(half);
        tx.addOutput(half, ADDRESS);
        tx.verify();
    }

    @Test(expected = VerificationException.UnexpectedCoinbaseInput.class)
    public void coinbaseInputInNonCoinbaseTX() throws Exception {
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[10]).build());
        tx.verify();
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooSmall() throws Exception {
        tx.clearInputs();
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().build());
        tx.verify();
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooLarge() throws Exception {
        tx.clearInputs();
        TransactionInput input = tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[99]).build());
        assertEquals(101, input.getScriptBytes().length);
        tx.verify();
    }

    @Test
    public void testEstimatedLockTime_WhenParameterSignifiesBlockHeight() {
        int TEST_LOCK_TIME = 20;
        Date now = Calendar.getInstance().getTime();

        BlockChain mockBlockChain = createMock(BlockChain.class);
        EasyMock.expect(mockBlockChain.estimateBlockTime(TEST_LOCK_TIME)).andReturn(now);

        Transaction tx = FakeTxBuilder.createFakeTx(UNITTEST);
        tx.setLockTime(TEST_LOCK_TIME); // less than five hundred million

        replay(mockBlockChain);

        assertEquals(tx.estimateLockTime(mockBlockChain), now);
    }

    @Test
    public void testOptimalEncodingMessageSize() {
        Transaction tx = new Transaction(UNITTEST);

        int length = tx.length;

        // add basic transaction input, check the length
        tx.addOutput(new TransactionOutput(UNITTEST, null, Coin.COIN, ADDRESS));
        length += getCombinedLength(tx.getOutputs());

        // add basic output, check the length
        length += getCombinedLength(tx.getInputs());

        // optimal encoding size should equal the length we just calculated
        assertEquals(tx.getOptimalEncodingMessageSize(), length);
    }

    private int getCombinedLength(List<? extends Message> list) {
        int sumOfAllMsgSizes = 0;
        for (Message m: list) { sumOfAllMsgSizes += m.getMessageSize() + 1; }
        return sumOfAllMsgSizes;
    }

    @Test
    public void testIsMatureReturnsFalseIfTransactionIsCoinbaseAndConfidenceTypeIsNotEqualToBuilding() {
        Transaction tx = FakeTxBuilder.createFakeCoinbaseTx(UNITTEST);

        tx.getConfidence().setConfidenceType(ConfidenceType.UNKNOWN);
        assertEquals(tx.isMature(), false);

        tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);
        assertEquals(tx.isMature(), false);

        tx.getConfidence().setConfidenceType(ConfidenceType.DEAD);
        assertEquals(tx.isMature(), false);
    }

    @Test
    public void testCLTVPaymentChannelTransactionSpending() {
        BigInteger time = BigInteger.valueOf(20);

        ECKey from = new ECKey(), to = new ECKey(), incorrect = new ECKey();
        Script outputScript = ScriptBuilder.createCLTVPaymentChannelOutput(time, from, to);

        Transaction tx = new Transaction(UNITTEST);
        tx.addInput(new TransactionInput(UNITTEST, tx, new byte[] {}));
        tx.getInput(0).setSequenceNumber(0);
        tx.setLockTime(time.subtract(BigInteger.ONE).longValue());
        TransactionSignature fromSig =
                tx.calculateSignature(
                        0,
                        from,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature toSig =
                tx.calculateSignature(
                        0,
                        to,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature incorrectSig =
                tx.calculateSignature(
                        0,
                        incorrect,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        Script scriptSig =
                ScriptBuilder.createCLTVPaymentChannelInput(fromSig, toSig);
        Script refundSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(fromSig);
        Script invalidScriptSig1 =
                ScriptBuilder.createCLTVPaymentChannelInput(fromSig, incorrectSig);
        Script invalidScriptSig2 =
                ScriptBuilder.createCLTVPaymentChannelInput(incorrectSig, toSig);

        try {
            scriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
        } catch (ScriptException e) {
            e.printStackTrace();
            fail("Settle transaction failed to correctly spend the payment channel");
        }

        try {
            refundSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Refund passed before expiry");
        } catch (ScriptException e) { }
        try {
            invalidScriptSig1.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig 1 passed");
        } catch (ScriptException e) { }
        try {
            invalidScriptSig2.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig 2 passed");
        } catch (ScriptException e) { }
    }

    @Test
    public void testCLTVPaymentChannelTransactionRefund() {
        BigInteger time = BigInteger.valueOf(20);

        ECKey from = new ECKey(), to = new ECKey(), incorrect = new ECKey();
        Script outputScript = ScriptBuilder.createCLTVPaymentChannelOutput(time, from, to);

        Transaction tx = new Transaction(UNITTEST);
        tx.addInput(new TransactionInput(UNITTEST, tx, new byte[] {}));
        tx.getInput(0).setSequenceNumber(0);
        tx.setLockTime(time.add(BigInteger.ONE).longValue());
        TransactionSignature fromSig =
                tx.calculateSignature(
                        0,
                        from,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature incorrectSig =
                tx.calculateSignature(
                        0,
                        incorrect,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        Script scriptSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(fromSig);
        Script invalidScriptSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(incorrectSig);

        try {
            scriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
        } catch (ScriptException e) {
            e.printStackTrace();
            fail("Refund failed to correctly spend the payment channel");
        }

        try {
            invalidScriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig passed");
        } catch (ScriptException e) { }
    }

    @Test
    public void witnessTransaction() {
        String hex = null;
        String hex2 = null;
        Transaction tx = null;

        // Roundtrip without witness
        hex = "0100000003362c10b042d48378b428d60c5c98d8b8aca7a03e1a2ca1048bfd469934bbda95010000008b483045022046c8bc9fb0e063e2fc8c6b1084afe6370461c16cbf67987d97df87827917d42d022100c807fa0ab95945a6e74c59838cc5f9e850714d8850cec4db1e7f3bcf71d5f5ef0141044450af01b4cc0d45207bddfb47911744d01f768d23686e9ac784162a5b3a15bc01e6653310bdd695d8c35d22e9bb457563f8de116ecafea27a0ec831e4a3e9feffffffffc19529a54ae15c67526cc5e20e535973c2d56ef35ff51bace5444388331c4813000000008b48304502201738185959373f04cc73dbbb1d061623d51dc40aac0220df56dabb9b80b72f49022100a7f76bde06369917c214ee2179e583fefb63c95bf876eb54d05dfdf0721ed772014104e6aa2cf108e1c650e12d8dd7ec0a36e478dad5a5d180585d25c30eb7c88c3df0c6f5fd41b3e70b019b777abd02d319bf724de184001b3d014cb740cb83ed21a6ffffffffbaae89b5d2e3ca78fd3f13cf0058784e7c089fb56e1e596d70adcfa486603967010000008b483045022055efbaddb4c67c1f1a46464c8f770aab03d6b513779ad48735d16d4c5b9907c2022100f469d50a5e5556fc2c932645f6927ac416aa65bc83d58b888b82c3220e1f0b73014104194b3f8aa08b96cae19b14bd6c32a92364bea3051cb9f018b03e3f09a57208ff058f4b41ebf96b9911066aef3be22391ac59175257af0984d1432acb8f2aefcaffffffff0340420f00000000001976a914c0fbb13eb10b57daa78b47660a4ffb79c29e2e6b88ac204e0000000000001976a9142cae94ffdc05f8214ccb2b697861c9c07e3948ee88ac1c2e0100000000001976a9146e03561cd4d6033456cc9036d409d2bf82721e9888ac00000000";
        tx = new Transaction(NetworkParameters.fromID(NetworkParameters.ID_MAINNET), HEX.decode(hex));
        assertFalse(tx.hasWitnesses());
        assertEquals(3, tx.getInputs().size());
        for (TransactionInput in : tx.getInputs())
            assertFalse(in.hasWitness());
        assertEquals(3, tx.getOutputs().size());
        hex2 = HEX.encode(tx.bitcoinSerialize());
        assertEquals(hex, hex2);
        assertEquals("Uncorrect hash", "38d4cfeb57d6685753b7a3b3534c3cb576c34ca7344cd4582f9613ebf0c2b02a",
                tx.getHash().toString());

        // Roundtrip with witness
        hex = "0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030cafb3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f06e1ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b42e7d033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e21125f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841b9874d913c430048c78a7b18baebdbea440588ac8096980000000000160014e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd8250f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a0ae50c276b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a83999738db0f7a6b91b2ec64f00db080000";
        tx = new Transaction(NetworkParameters.fromID(NetworkParameters.ID_MAINNET), HEX.decode(hex));
        assertTrue(tx.hasWitnesses());
        assertEquals(2, tx.getInputs().size());
        assertTrue(tx.getInput(0).hasWitness());
        assertFalse(tx.getInput(1).hasWitness());
        assertEquals(2, tx.getOutputs().size());
        hex2 = HEX.encode(tx.bitcoinSerialize());
        assertEquals(hex, hex2);
        assertEquals("Uncorrect hash", "99e7484eafb6e01622c395c8cae7cb9f8822aab6ba993696b39df8b60b0f4b11",
                tx.getHash().toString());
    }

    @Test
    public void testToStringWhenLockTimeIsSpecifiedInBlockHeight() {
        Transaction tx = FakeTxBuilder.createFakeTx(UNITTEST);
        TransactionInput input = tx.getInput(0);
        input.setSequenceNumber(42);

        int TEST_LOCK_TIME = 20;
        tx.setLockTime(TEST_LOCK_TIME);

        Calendar cal = Calendar.getInstance();
        cal.set(2085, 10, 4, 17, 53, 21);
        cal.set(Calendar.MILLISECOND, 0);

        BlockChain mockBlockChain = createMock(BlockChain.class);
        EasyMock.expect(mockBlockChain.estimateBlockTime(TEST_LOCK_TIME)).andReturn(cal.getTime());

        replay(mockBlockChain);

        String str = tx.toString(mockBlockChain);

        assertEquals(str.contains("block " + TEST_LOCK_TIME), true);
        assertEquals(str.contains("estimated to be reached at"), true);
    }

    @Test
    public void testToStringWhenIteratingOverAnInputCatchesAnException() {
        Transaction tx = FakeTxBuilder.createFakeTx(UNITTEST);
        TransactionInput ti = new TransactionInput(UNITTEST, tx, new byte[0]) {
            @Override
            public Script getScriptSig() throws ScriptException {
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "");
            }
        };

        tx.addInput(ti);
        assertEquals(tx.toString().contains("[exception: "), true);
    }

    @Test
    public void testToStringWhenThereAreZeroInputs() {
        Transaction tx = new Transaction(UNITTEST);
        assertEquals(tx.toString().contains("No inputs!"), true);
    }

    @Test
    public void testTheTXByHeightComparator() {
        Transaction tx1 = FakeTxBuilder.createFakeTx(UNITTEST);
        tx1.getConfidence().setAppearedAtChainHeight(1);

        Transaction tx2 = FakeTxBuilder.createFakeTx(UNITTEST);
        tx2.getConfidence().setAppearedAtChainHeight(2);

        Transaction tx3 = FakeTxBuilder.createFakeTx(UNITTEST);
        tx3.getConfidence().setAppearedAtChainHeight(3);

        SortedSet<Transaction> set = new TreeSet<>(Transaction.SORT_TX_BY_HEIGHT);
        set.add(tx2);
        set.add(tx1);
        set.add(tx3);

        Iterator<Transaction> iterator = set.iterator();

        assertEquals(tx1.equals(tx2), false);
        assertEquals(tx1.equals(tx3), false);
        assertEquals(tx1.equals(tx1), true);

        assertEquals(iterator.next().equals(tx3), true);
        assertEquals(iterator.next().equals(tx2), true);
        assertEquals(iterator.next().equals(tx1), true);
        assertEquals(iterator.hasNext(), false);
    }

    @Test(expected = ScriptException.class)
    public void testAddSignedInputThrowsExceptionWhenScriptIsNotToRawPubKeyAndIsNotToAddress() {
        ECKey key = new ECKey();
        Address addr = LegacyAddress.fromKey(UNITTEST, key);
        Transaction fakeTx = FakeTxBuilder.createFakeTx(UNITTEST, Coin.COIN, addr);

        Transaction tx = new Transaction(UNITTEST);
        tx.addOutput(fakeTx.getOutput(0));

        Script script = ScriptBuilder.createOpReturnScript(new byte[0]);

        tx.addSignedInput(fakeTx.getOutput(0).getOutPointFor(), script, key);
    }

    @Test
    public void testPrioSizeCalc() throws Exception {
        Transaction tx1 = FakeTxBuilder.createFakeTx(UNITTEST, Coin.COIN, ADDRESS);
        int size1 = tx1.getMessageSize();
        int size2 = tx1.getMessageSizeForPriorityCalc();
        assertEquals(113, size1 - size2);
        tx1.getInput(0).setScriptSig(new Script(new byte[109]));
        assertEquals(78, tx1.getMessageSizeForPriorityCalc());
        tx1.getInput(0).setScriptSig(new Script(new byte[110]));
        assertEquals(78, tx1.getMessageSizeForPriorityCalc());
        tx1.getInput(0).setScriptSig(new Script(new byte[111]));
        assertEquals(79, tx1.getMessageSizeForPriorityCalc());
    }

    @Test
    public void testCoinbaseHeightCheck() throws VerificationException {
        // Coinbase transaction from block 300,000
        final byte[] transactionBytes = HEX.decode(
                "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4803e09304062f503253482f0403c86d53087ceca141295a00002e522cfabe6d6d7561cf262313da1144026c8f7a43e3899c44f6145f39a36507d36679a8b7006104000000000000000000000001c8704095000000001976a91480ad90d403581fa3bf46086a91b2d9d4125db6c188ac00000000");
        final int height = 300000;
        final Transaction transaction = UNITTEST.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.checkCoinBaseHeight(height);
    }

    /**
     * Test a coinbase transaction whose script has nonsense after the block height.
     * See https://github.com/bitcoinj/bitcoinj/issues/1097
     */
    @Test
    public void testCoinbaseHeightCheckWithDamagedScript() throws VerificationException {
        // Coinbase transaction from block 224,430
        final byte[] transactionBytes = HEX.decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3b03ae6c0300044bd7031a0400000000522cfabe6d6d00000000000000b7b8bf0100000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff01e0587597000000001976a91421c0d001728b3feaf115515b7c135e779e9f442f88ac00000000");
        final int height = 224430;
        final Transaction transaction = UNITTEST.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.checkCoinBaseHeight(height);
    }

    @Test
    public void optInFullRBF() {
        // a standard transaction as wallets would create
        Transaction tx = FakeTxBuilder.createFakeTx(UNITTEST);
        assertFalse(tx.isOptInFullRBF());

        tx.getInputs().get(0).setSequenceNumber(TransactionInput.NO_SEQUENCE - 2);
        assertTrue(tx.isOptInFullRBF());
    }

    /**
     * Ensure that hashForSignature() doesn't modify a transaction's data, which could wreak multithreading havoc.
     */
    @Test
    public void testHashForSignatureThreadSafety() {
        Block genesis = UNITTEST.getGenesisBlock();
        Block block1 = genesis.createNextBlock(LegacyAddress.fromKey(UNITTEST, new ECKey()),
                    genesis.getTransactions().get(0).getOutput(0).getOutPointFor());

        final Transaction tx = block1.getTransactions().get(1);
        final String txHash = tx.getHashAsString();
        final String txNormalizedHash = tx.hashForSignature(
                0,
                new byte[0],
                Transaction.SigHash.ALL.byteValue())
                .toString();

        for (int i = 0; i < 100; i++) {
            // ensure the transaction object itself was not modified; if it was, the hash will change
            assertEquals(txHash, tx.getHashAsString());
            new Thread(){
                public void run() {
                    assertEquals(
                            txNormalizedHash,
                            tx.hashForSignature(
                                    0,
                                    new byte[0],
                                    Transaction.SigHash.ALL.byteValue())
                                    .toString());
                }
            };
        }
    }

    @Test
    public void parseTransactionWithHugeDeclaredInputsSize() throws Exception {
        Transaction tx = new HugeDeclaredSizeTransaction(UNITTEST, true, false, false);
        byte[] serializedTx = tx.bitcoinSerialize();
        try {
            new Transaction(UNITTEST, serializedTx);
            fail("We expect ProtocolException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (ProtocolException e) {
            //Expected, do nothing
        }
    }

    @Test
    public void parseTransactionWithHugeDeclaredOutputsSize() throws Exception {
        Transaction tx = new HugeDeclaredSizeTransaction(UNITTEST, false, true, false);
        byte[] serializedTx = tx.bitcoinSerialize();
        try {
            new Transaction(UNITTEST, serializedTx);
            fail("We expect ProtocolException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (ProtocolException e) {
            //Expected, do nothing
        }
    }

    @Test
    public void parseTransactionWithHugeDeclaredWitnessPushCountSize() throws Exception {
        Transaction tx = new HugeDeclaredSizeTransaction(UNITTEST, false, false, true);
        byte[] serializedTx = tx.bitcoinSerialize();
        try {
            new Transaction(UNITTEST, serializedTx);
            fail("We expect ProtocolException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (ProtocolException e) {
            //Expected, do nothing
        }
    }

    private static class HugeDeclaredSizeTransaction extends Transaction {

        private boolean hackInputsSize;
        private boolean hackOutputsSize;
        private boolean hackWitnessPushCountSize;

        public HugeDeclaredSizeTransaction(NetworkParameters params, boolean hackInputsSize, boolean hackOutputsSize, boolean hackWitnessPushCountSize) {
            super(params);
            this.protocolVersion = NetworkParameters.ProtocolVersion.WITNESS_VERSION.getBitcoinProtocolVersion();
            Transaction inputTx = new Transaction(params);
            inputTx.addOutput(Coin.FIFTY_COINS, LegacyAddress.fromKey(params, ECKey.fromPrivate(BigInteger.valueOf(123456))));
            this.addInput(inputTx.getOutput(0));
            this.getInput(0).disconnect();
            TransactionWitness witness = new TransactionWitness(1);
            witness.setPush(0, new byte[] {0});
            this.getInput(0).setWitness(witness);
            Address to = LegacyAddress.fromKey(params, ECKey.fromPrivate(BigInteger.valueOf(1000)));
            this.addOutput(Coin.COIN, to);

            this.hackInputsSize = hackInputsSize;
            this.hackOutputsSize = hackOutputsSize;
            this.hackWitnessPushCountSize = hackWitnessPushCountSize;
        }

        @Override
        protected void bitcoinSerializeToStream(OutputStream stream, boolean useSegwit) throws IOException {
            // version
            uint32ToByteStreamLE(getVersion(), stream);
            // marker, flag
            if (useSegwit) {
                stream.write(0);
                stream.write(1);
            }
            // txin_count, txins
            long inputsSize = hackInputsSize ? Integer.MAX_VALUE : getInputs().size();
            stream.write(new VarInt(inputsSize).encode());
            for (TransactionInput in : getInputs())
                in.bitcoinSerialize(stream);
            // txout_count, txouts
            long outputsSize = hackOutputsSize ? Integer.MAX_VALUE : getOutputs().size();
            stream.write(new VarInt(outputsSize).encode());
            for (TransactionOutput out : getOutputs())
                out.bitcoinSerialize(stream);
            // script_witnisses
            if (useSegwit) {
                for (TransactionInput in : getInputs()) {
                    TransactionWitness witness = in.getWitness();
                    long pushCount = hackWitnessPushCountSize ? Integer.MAX_VALUE : witness.getPushCount();
                    stream.write(new VarInt(pushCount).encode());
                    for (int i = 0; i < witness.getPushCount(); i++) {
                        byte[] push = witness.getPush(i);
                        stream.write(new VarInt(push.length).encode());
                        stream.write(push);
                    }

                    in.getWitness().bitcoinSerializeToStream(stream);
                }
            }
            // lock_time
            uint32ToByteStreamLE(getLockTime(), stream);
        }
    }
}
