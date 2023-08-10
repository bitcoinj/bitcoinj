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

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.TransactionConfidence.ConfidenceType;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.crypto.internal.CryptoUtils;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptError;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.wallet.Wallet;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.IntFunction;
import java.util.stream.Stream;

import org.bitcoinj.base.internal.ByteUtils;
import static org.bitcoinj.base.internal.ByteUtils.writeInt32LE;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Just check the Transaction.verify() method. Most methods that have complicated logic in Transaction are tested
 * elsewhere, e.g. signing and hashing are well exercised by the wallet tests, the full block chain tests and so on.
 * The verify method is also exercised by the full block chain tests, but it can also be used by API users alone,
 * so we make sure to cover it here as well.
 */
public class TransactionTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final Address ADDRESS = new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);

    @Before
    public void setUp() {
        Context.propagate(new Context());
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyOutputs() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx.clearOutputs();
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyInputs() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx.clearInputs();
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test(expected = VerificationException.LargerThanMaxBlockSize.class)
    public void tooHuge() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx.getInput(0).setScriptBytes(new byte[Block.MAX_BLOCK_SIZE]);
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test(expected = VerificationException.DuplicatedOutPoint.class)
    public void duplicateOutPoint() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        TransactionInput input = tx.getInput(0);
        input.setScriptBytes(new byte[1]);
        tx.addInput(input);
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test(expected = VerificationException.NegativeValueOutput.class)
    public void negativeOutput() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx.getOutput(0).setValue(Coin.NEGATIVE_SATOSHI);
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test(expected = VerificationException.ExcessiveValue.class)
    public void exceedsMaxMoney2() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        Coin half = BitcoinNetwork.MAX_MONEY.divide(2).add(Coin.SATOSHI);
        tx.getOutput(0).setValue(half);
        tx.addOutput(half, ADDRESS);
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test(expected = VerificationException.UnexpectedCoinbaseInput.class)
    public void coinbaseInputInNonCoinbaseTX() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[10]).build());
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooSmall() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx.clearInputs();
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().build());
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooLarge() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx.clearInputs();
        TransactionInput input = tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[99]).build());
        assertEquals(101, input.getScriptBytes().length);
        Transaction.verify(TESTNET.network(), tx);
    }

    @Test
    public void testEstimatedLockTime_WhenParameterSignifiesBlockHeight() {
        int TEST_LOCK_TIME = 20;
        Instant now = TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS);

        BlockChain mockBlockChain = createMock(BlockChain.class);
        EasyMock.expect(mockBlockChain.estimateBlockTimeInstant(TEST_LOCK_TIME)).andReturn(now);

        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx.setLockTime(TEST_LOCK_TIME); // less than five hundred million

        replay(mockBlockChain);

        assertEquals(tx.estimateUnlockTime(mockBlockChain), now);
    }

    @Test
    public void testMessageSize() {
        Transaction tx = new Transaction();
        int length = tx.messageSize();

        // add fake transaction input
        TransactionInput input = new TransactionInput(null, ScriptBuilder.createEmpty().program(),
                new TransactionOutPoint(0, Sha256Hash.ZERO_HASH));
        tx.addInput(input);
        length += input.messageSize();

        // add fake transaction output
        TransactionOutput output = new TransactionOutput(null, Coin.COIN, ADDRESS);
        tx.addOutput(output);
        length += output.messageSize();

        // message size has now grown
        assertEquals(length, tx.messageSize());
    }

    @Test
    public void testIsMatureReturnsFalseIfTransactionIsCoinbaseAndConfidenceTypeIsNotEqualToBuilding() {
        Wallet wallet = Wallet.createBasic(BitcoinNetwork.TESTNET);
        Transaction tx = FakeTxBuilder.createFakeCoinbaseTx();

        tx.getConfidence().setConfidenceType(ConfidenceType.UNKNOWN);
        assertFalse(wallet.isTransactionMature(tx));

        tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);
        assertFalse(wallet.isTransactionMature(tx));

        tx.getConfidence().setConfidenceType(ConfidenceType.DEAD);
        assertFalse(wallet.isTransactionMature(tx));
    }

    @Test
    public void addSignedInput_P2PKH() {
        final Address toAddr = new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        final Sha256Hash utxo_id = Sha256Hash.wrap("81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48");
        final Coin inAmount = Coin.ofSat(91234);
        final Coin outAmount = Coin.ofSat(91234);

        ECKey fromKey = new ECKey();
        Address fromAddress = fromKey.toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        Transaction tx = new Transaction();
        TransactionOutPoint outPoint = new TransactionOutPoint(0, utxo_id);
        TransactionOutput output = new TransactionOutput(null, inAmount, fromAddress);
        tx.addOutput(outAmount, toAddr);
        TransactionInput input = tx.addSignedInput(outPoint, ScriptBuilder.createOutputScript(fromAddress), inAmount, fromKey);

        // verify signature
        input.getScriptSig().correctlySpends(tx, 0, null, null, ScriptBuilder.createOutputScript(fromAddress), null);

        byte[] rawTx = tx.serialize();

        assertNotNull(rawTx);
    }

    @Test
    public void addSignedInput_P2WPKH() {
        final Address toAddr = new ECKey().toAddress(ScriptType.P2WPKH, BitcoinNetwork.TESTNET);
        final Sha256Hash utxo_id = Sha256Hash.wrap("81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48");
        final Coin inAmount = Coin.ofSat(91234);
        final Coin outAmount = Coin.ofSat(91234);

        ECKey fromKey = new ECKey();
        Address fromAddress = fromKey.toAddress(ScriptType.P2WPKH, BitcoinNetwork.TESTNET);
        Transaction tx = new Transaction();
        TransactionOutPoint outPoint = new TransactionOutPoint(0, utxo_id);
        tx.addOutput(outAmount, toAddr);
        TransactionInput input = tx.addSignedInput(outPoint, ScriptBuilder.createOutputScript(fromAddress), inAmount, fromKey);

        // verify signature
        input.getScriptSig().correctlySpends(tx, 0, input.getWitness(), input.getValue(),
                ScriptBuilder.createOutputScript(fromAddress), null);

        byte[] rawTx = tx.serialize();

        assertNotNull(rawTx);
    }

    @Test
    public void witnessTransaction() {
        String hex;
        Transaction tx;

        // Roundtrip without witness
        hex = "0100000003362c10b042d48378b428d60c5c98d8b8aca7a03e1a2ca1048bfd469934bbda95010000008b483045022046c8bc9fb0e063e2fc8c6b1084afe6370461c16cbf67987d97df87827917d42d022100c807fa0ab95945a6e74c59838cc5f9e850714d8850cec4db1e7f3bcf71d5f5ef0141044450af01b4cc0d45207bddfb47911744d01f768d23686e9ac784162a5b3a15bc01e6653310bdd695d8c35d22e9bb457563f8de116ecafea27a0ec831e4a3e9feffffffffc19529a54ae15c67526cc5e20e535973c2d56ef35ff51bace5444388331c4813000000008b48304502201738185959373f04cc73dbbb1d061623d51dc40aac0220df56dabb9b80b72f49022100a7f76bde06369917c214ee2179e583fefb63c95bf876eb54d05dfdf0721ed772014104e6aa2cf108e1c650e12d8dd7ec0a36e478dad5a5d180585d25c30eb7c88c3df0c6f5fd41b3e70b019b777abd02d319bf724de184001b3d014cb740cb83ed21a6ffffffffbaae89b5d2e3ca78fd3f13cf0058784e7c089fb56e1e596d70adcfa486603967010000008b483045022055efbaddb4c67c1f1a46464c8f770aab03d6b513779ad48735d16d4c5b9907c2022100f469d50a5e5556fc2c932645f6927ac416aa65bc83d58b888b82c3220e1f0b73014104194b3f8aa08b96cae19b14bd6c32a92364bea3051cb9f018b03e3f09a57208ff058f4b41ebf96b9911066aef3be22391ac59175257af0984d1432acb8f2aefcaffffffff0340420f00000000001976a914c0fbb13eb10b57daa78b47660a4ffb79c29e2e6b88ac204e0000000000001976a9142cae94ffdc05f8214ccb2b697861c9c07e3948ee88ac1c2e0100000000001976a9146e03561cd4d6033456cc9036d409d2bf82721e9888ac00000000";
        tx = Transaction.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
        assertFalse(tx.hasWitnesses());
        assertEquals(3, tx.getInputs().size());
        for (TransactionInput in : tx.getInputs())
            assertFalse(in.hasWitness());
        assertEquals(3, tx.getOutputs().size());
        assertEquals(hex, ByteUtils.formatHex(tx.serialize()));
        assertEquals("Uncorrect hash", "38d4cfeb57d6685753b7a3b3534c3cb576c34ca7344cd4582f9613ebf0c2b02a",
                tx.getTxId().toString());
        assertEquals(tx.getWTxId(), tx.getTxId());
        assertEquals(hex.length() / 2, tx.messageSize());

        // Roundtrip with witness
        hex = "0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030cafb3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f06e1ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b42e7d033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e21125f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841b9874d913c430048c78a7b18baebdbea440588ac8096980000000000160014e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd8250f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a0ae50c276b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a83999738db0f7a6b91b2ec64f00db080000";
        tx = Transaction.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
        assertTrue(tx.hasWitnesses());
        assertEquals(2, tx.getInputs().size());
        assertTrue(tx.getInput(0).hasWitness());
        assertFalse(tx.getInput(1).hasWitness());
        assertEquals(2, tx.getOutputs().size());
        assertEquals(hex, ByteUtils.formatHex(tx.serialize()));
        assertEquals("Uncorrect hash", "99e7484eafb6e01622c395c8cae7cb9f8822aab6ba993696b39df8b60b0f4b11",
                tx.getTxId().toString());
        assertNotEquals(tx.getWTxId(), tx.getTxId());
        assertEquals(hex.length() / 2, tx.messageSize());
    }

    @Test
    public void testWitnessSignatureP2WPKH() {
        // test vector P2WPKH from:
        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
        String txHex = "01000000" // version
                + "02" // num txIn
                + "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" + "00000000" + "00" + "eeffffff" // txIn
                + "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" + "01000000" + "00" + "ffffffff" // txIn
                + "02" // num txOut
                + "202cb20600000000" + "1976a914" + "8280b37df378db99f66f85c95a783a76ac7a6d59" + "88ac" // txOut
                + "9093510d00000000" + "1976a914" + "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159" + "88ac" // txOut
                + "11000000"; // nLockTime
        Transaction tx = Transaction.read(ByteBuffer.wrap(ByteUtils.parseHex(txHex)));
        assertEquals(txHex, ByteUtils.formatHex(tx.serialize()));
        assertEquals(txHex.length() / 2, tx.messageSize());
        assertEquals(2, tx.getInputs().size());
        assertEquals(2, tx.getOutputs().size());
        TransactionInput txIn0 = tx.getInput(0);
        TransactionInput txIn1 = tx.getInput(1);

        ECKey key0 = ECKey.fromPrivate(ByteUtils.parseHex("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866"));
        Script scriptPubKey0 = ScriptBuilder.createP2PKOutputScript(key0);
        assertEquals("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
                ByteUtils.formatHex(scriptPubKey0.program()));
        ECKey key1 = ECKey.fromPrivate(ByteUtils.parseHex("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"));
        assertEquals("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357", key1.getPublicKeyAsHex());
        Script scriptPubKey1 = ScriptBuilder.createP2WPKHOutputScript(key1);
        assertEquals("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1", ByteUtils.formatHex(scriptPubKey1.program()));
        txIn1.connect(new Transaction().addOutput(Coin.COIN.multiply(6), scriptPubKey1));

        assertEquals("63cec688ee06a91e913875356dd4dea2f8e0f2a2659885372da2a37e32c7532e",
                tx.hashForSignature(0, scriptPubKey0, Transaction.SigHash.ALL, false).toString());
        TransactionSignature txSig0 = tx.calculateSignature(0, key0,
                scriptPubKey0,
                Transaction.SigHash.ALL, false);
        assertEquals("30450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01",
                ByteUtils.formatHex(txSig0.encodeToBitcoin()));

        Script witnessScript = ScriptBuilder.createP2PKHOutputScript(key1);
        assertEquals("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac",
                ByteUtils.formatHex(witnessScript.program()));

        assertEquals("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
                tx.hashForWitnessSignature(1, witnessScript, txIn1.getValue(), Transaction.SigHash.ALL, false).toString());
        TransactionSignature txSig1 = tx.calculateWitnessSignature(1, key1,
                witnessScript, txIn1.getValue(),
                Transaction.SigHash.ALL, false);
        assertEquals("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
                        + "01",
                ByteUtils.formatHex(txSig1.encodeToBitcoin()));

        assertFalse(correctlySpends(txIn0, scriptPubKey0, 0));
        txIn0.setScriptSig(new ScriptBuilder().data(txSig0.encodeToBitcoin()).build());
        assertTrue(correctlySpends(txIn0, scriptPubKey0, 0));

        assertFalse(correctlySpends(txIn1, scriptPubKey1, 1));
        txIn1.setWitness(TransactionWitness.redeemP2WPKH(txSig1, key1));
        // no redeem script for p2wpkh
        assertTrue(correctlySpends(txIn1, scriptPubKey1, 1));

        String signedTxHex = "01000000" // version
                + "00" // marker
                + "01" // flag
                + "02" // num txIn
                + "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" + "00000000"
                + "494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01"
                + "eeffffff" // txIn
                + "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" + "01000000" + "00" + "ffffffff" // txIn
                + "02" // num txOut
                + "202cb20600000000" + "1976a914" + "8280b37df378db99f66f85c95a783a76ac7a6d59" + "88ac" // txOut
                + "9093510d00000000" + "1976a914" + "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159" + "88ac" // txOut
                + "00" // witness (empty)
                + "02" // witness (2 pushes)
                + "47" // push length
                + "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01" // push
                + "21" // push length
                + "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357" // push
                + "11000000"; // nLockTime
        assertEquals(signedTxHex, ByteUtils.formatHex(tx.serialize()));
        assertEquals(signedTxHex.length() / 2, tx.messageSize());
    }

    @Test
    public void testWitnessSignatureP2SH_P2WPKH() {
        // test vector P2SH-P2WPKH from:
        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
        String txHex = "01000000" // version
                + "01" // num txIn
                + "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477" + "01000000" + "00" + "feffffff" // txIn
                + "02" // num txOut
                + "b8b4eb0b00000000" + "1976a914" + "a457b684d7f0d539a46a45bbc043f35b59d0d963" + "88ac" // txOut
                + "0008af2f00000000" + "1976a914" + "fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c" + "88ac" // txOut
                + "92040000"; // nLockTime
        Transaction tx = Transaction.read(ByteBuffer.wrap(ByteUtils.parseHex(txHex)));
        assertEquals(txHex, ByteUtils.formatHex(tx.serialize()));
        assertEquals(txHex.length() / 2, tx.messageSize());
        assertEquals(1, tx.getInputs().size());
        assertEquals(2, tx.getOutputs().size());
        TransactionInput txIn = tx.getInput(0);

        ECKey key = ECKey.fromPrivate(
                ByteUtils.parseHex("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"));
        assertEquals("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873",
                key.getPublicKeyAsHex());

        Script redeemScript = ScriptBuilder.createP2WPKHOutputScript(key);
        assertEquals("001479091972186c449eb1ded22b78e40d009bdf0089",
                ByteUtils.formatHex(redeemScript.program()));

        byte[] p2wpkhHash = CryptoUtils.sha256hash160(redeemScript.program());
        Script scriptPubKey = ScriptBuilder.createP2SHOutputScript(p2wpkhHash);
        assertEquals("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387",
                ByteUtils.formatHex(scriptPubKey.program()));

        Script witnessScript = ScriptBuilder.createP2PKHOutputScript(key);
        assertEquals("76a91479091972186c449eb1ded22b78e40d009bdf008988ac",
                ByteUtils.formatHex(witnessScript.program()));

        assertEquals("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
                tx.hashForWitnessSignature(0, witnessScript, Coin.COIN.multiply(10), Transaction.SigHash.ALL, false)
                        .toString());
        TransactionSignature txSig = tx.calculateWitnessSignature(0, key,
                witnessScript, Coin.COIN.multiply(10),
                Transaction.SigHash.ALL, false);
        assertEquals("3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb"
                        + "01",
                ByteUtils.formatHex(txSig.encodeToBitcoin()));

        assertFalse(correctlySpends(txIn, scriptPubKey, 0));
        txIn.setWitness(TransactionWitness.redeemP2WPKH(txSig, key));
        txIn.setScriptSig(new ScriptBuilder().data(redeemScript.program()).build());
        assertTrue(correctlySpends(txIn, scriptPubKey, 0));

        String signedTxHex = "01000000" // version
                + "00" // marker
                + "01" // flag
                + "01" // num txIn
                + "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477" + "01000000" // txIn
                + "1716001479091972186c449eb1ded22b78e40d009bdf0089" + "feffffff" // txIn
                + "02" // num txOut
                + "b8b4eb0b00000000" + "1976a914" + "a457b684d7f0d539a46a45bbc043f35b59d0d963" + "88ac" // txOut
                + "0008af2f00000000" + "1976a914" + "fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c" + "88ac" // txOut
                + "02" // witness (2 pushes)
                + "47" // push length
                + "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01" // push
                + "21" // push length
                + "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873" // push
                + "92040000"; // nLockTime
        assertEquals(signedTxHex, ByteUtils.formatHex(tx.serialize()));
        assertEquals(signedTxHex.length() / 2, tx.messageSize());
    }

    @Test
    public void testWitnessSignatureP2SH_P2WSHSingleAnyoneCanPay() throws Exception {
        // test vector P2SH-P2WSH from the final example at:
        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wsh
        String txHex = "01000000" // version
                + "01" // num txIn
                + "36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e" + "01000000" + "00" + "ffffffff" // txIn
                + "02" // num txOut
                + "00e9a43500000000" + "1976a914" + "389ffce9cd9ae88dcc0631e88a821ffdbe9bfe26" + "88ac" // txOut
                + "c0832f0500000000" + "1976a914" + "7480a33f950689af511e6e84c138dbbd3c3ee415" + "88ac" // txOut
                + "00000000"; // nLockTime
        Transaction tx = Transaction.read(ByteBuffer.wrap(ByteUtils.parseHex(txHex)));

        ECKey pubKey = ECKey.fromPublicOnly(ByteUtils.parseHex(
                "02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b"));
        Script script = Script.parse(ByteUtils.parseHex(
                "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"));
        Sha256Hash hash = tx.hashForWitnessSignature(0, script, Coin.valueOf(987654321L),
                Transaction.SigHash.SINGLE, true);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(ByteUtils.parseHex(
                "30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783"), true, true);
        assertTrue(pubKey.verify(hash, signature));
    }

    private boolean correctlySpends(TransactionInput txIn, Script scriptPubKey, int inputIndex) {
        try {
            txIn.getScriptSig().correctlySpends(txIn.getParentTransaction(), inputIndex, txIn.getWitness(),
                    txIn.getValue(), scriptPubKey, Script.ALL_VERIFY_FLAGS);
            return true;
        } catch (ScriptException x) {
            return false;
        }
    }

    @Test
    public void testToString() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        int lengthWithAddresses = tx.toString(null, BitcoinNetwork.TESTNET).length();
        int lengthWithoutAddresses = tx.toString(null, null).length();
        assertTrue(lengthWithAddresses > lengthWithoutAddresses);
    }

    @Test
    public void testToStringWhenLockTimeIsSpecifiedInBlockHeight() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        TransactionInput input = tx.getInput(0);
        input.setSequenceNumber(42);

        int TEST_LOCK_TIME = 20;
        tx.setLockTime(TEST_LOCK_TIME);

        Calendar cal = Calendar.getInstance();
        cal.set(2085, 10, 4, 17, 53, 21);
        cal.set(Calendar.MILLISECOND, 0);

        BlockChain mockBlockChain = createMock(BlockChain.class);
        EasyMock.expect(mockBlockChain.estimateBlockTimeInstant(TEST_LOCK_TIME)).andReturn(Instant.ofEpochMilli(cal.getTimeInMillis()));

        replay(mockBlockChain);

        String str = tx.toString(mockBlockChain, BitcoinNetwork.TESTNET);

        assertTrue(str.contains("block " + TEST_LOCK_TIME));
        assertTrue(str.contains("estimated to be reached at"));
    }

    @Test
    public void testToStringWhenIteratingOverAnInputCatchesAnException() {
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        TransactionInput ti = new TransactionInput(tx, new byte[0], TransactionOutPoint.UNCONNECTED) {
            @Override
            public Script getScriptSig() throws ScriptException {
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "");
            }
        };

        tx.addInput(ti);
        assertTrue(tx.toString().contains("[exception: "));
    }

    @Test
    public void testToStringWhenThereAreZeroInputs() {
        Transaction tx = new Transaction();
        assertTrue(tx.toString().contains("No inputs!"));
    }

    @Test
    public void testTheTXByHeightComparator() {
        Transaction tx1 = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx1.getConfidence().setAppearedAtChainHeight(1);

        Transaction tx2 = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx2.getConfidence().setAppearedAtChainHeight(2);

        Transaction tx3 = FakeTxBuilder.createFakeTx(TESTNET.network());
        tx3.getConfidence().setAppearedAtChainHeight(3);

        SortedSet<Transaction> set = new TreeSet<>(Transaction.SORT_TX_BY_HEIGHT);
        set.add(tx2);
        set.add(tx1);
        set.add(tx3);

        Iterator<Transaction> iterator = set.iterator();

        assertFalse(tx1.equals(tx2));
        assertFalse(tx1.equals(tx3));
        assertTrue(tx1.equals(tx1));

        assertTrue(iterator.next().equals(tx3));
        assertTrue(iterator.next().equals(tx2));
        assertTrue(iterator.next().equals(tx1));
        assertFalse(iterator.hasNext());
    }

    @Test(expected = ScriptException.class)
    public void testAddSignedInputThrowsExceptionWhenScriptIsNotToRawPubKeyAndIsNotToAddress() {
        ECKey key = new ECKey();
        Address addr = key.toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        TransactionOutput fakeOutput = FakeTxBuilder.createFakeTx(TESTNET.network(), Coin.COIN, addr).getOutput(0);

        Transaction tx = new Transaction();
        tx.addOutput(fakeOutput);

        Script script = ScriptBuilder.createOpReturnScript(new byte[0]);

        tx.addSignedInput(fakeOutput.getOutPointFor(), script, fakeOutput.getValue(), key);
    }

    @Test
    public void testPrioSizeCalc() {
        Transaction tx1 = FakeTxBuilder.createFakeTx(TESTNET.network(), Coin.COIN, ADDRESS);
        int size1 = tx1.messageSize();
        int size2 = tx1.getMessageSizeForPriorityCalc();
        assertEquals(113, size1 - size2);
        tx1.getInput(0).setScriptSig(Script.parse(new byte[109]));
        assertEquals(78, tx1.getMessageSizeForPriorityCalc());
        tx1.getInput(0).setScriptSig(Script.parse(new byte[110]));
        assertEquals(78, tx1.getMessageSizeForPriorityCalc());
        tx1.getInput(0).setScriptSig(Script.parse(new byte[111]));
        assertEquals(79, tx1.getMessageSizeForPriorityCalc());
    }

    @Test
    public void testCoinbaseHeightCheck() {
        // Coinbase transaction from block 300,000
        ByteBuffer transactionBytes = ByteBuffer.wrap(ByteUtils.parseHex(
                "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4803e09304062f503253482f0403c86d53087ceca141295a00002e522cfabe6d6d7561cf262313da1144026c8f7a43e3899c44f6145f39a36507d36679a8b7006104000000000000000000000001c8704095000000001976a91480ad90d403581fa3bf46086a91b2d9d4125db6c188ac00000000"));
        final int height = 300000;
        final Transaction transaction = TESTNET.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.checkCoinBaseHeight(height);
    }

    /**
     * Test a coinbase transaction whose script has nonsense after the block height.
     * See https://github.com/bitcoinj/bitcoinj/issues/1097
     */
    @Test
    public void testCoinbaseHeightCheckWithDamagedScript() {
        // Coinbase transaction from block 224,430
        ByteBuffer transactionBytes = ByteBuffer.wrap(ByteUtils.parseHex(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3b03ae6c0300044bd7031a0400000000522cfabe6d6d00000000000000b7b8bf0100000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff01e0587597000000001976a91421c0d001728b3feaf115515b7c135e779e9f442f88ac00000000"));
        final int height = 224430;
        final Transaction transaction = TESTNET.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.checkCoinBaseHeight(height);
    }

    @Test
    public void optInFullRBF() {
        // a standard transaction as wallets would create
        Transaction tx = FakeTxBuilder.createFakeTx(TESTNET.network());
        assertFalse(tx.isOptInFullRBF());

        tx.getInput(0).setSequenceNumber(TransactionInput.NO_SEQUENCE - 2);
        assertTrue(tx.isOptInFullRBF());
    }

    /**
     * Ensure that hashForSignature() doesn't modify a transaction's data, which could wreak multithreading havoc.
     */
    @Test
    public void testHashForSignatureThreadSafety() throws Exception {
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        Block genesis = TESTNET.getGenesisBlock();
        Block block1 = genesis.createNextBlock(new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET),
                    genesis.getTransactions().get(0).getOutput(0).getOutPointFor());

        final Transaction tx = block1.getTransactions().get(1);
        final Sha256Hash txHash = tx.getTxId();
        final String txNormalizedHash = tx.hashForSignature(
                0,
                new byte[0],
                Transaction.SigHash.ALL.byteValue())
                .toString();
        final Runnable runnable = () -> {
            // ensure the transaction object itself was not modified; if it was, the hash will change
            assertEquals(txHash, tx.getTxId());
            assertEquals(
                    txNormalizedHash,
                    tx.hashForSignature(
                                    0,
                                    new byte[0],
                                    Transaction.SigHash.ALL.byteValue())
                            .toString());
            assertEquals(txHash, tx.getTxId());
        };
        final int nThreads = 100;
        ExecutorService executor = Executors.newFixedThreadPool(nThreads); // do our best to run as parallel as possible
        // Build a stream of nThreads CompletableFutures and convert to an array
        CompletableFuture<Void>[] results = Stream
                .generate(() -> CompletableFuture.runAsync(runnable, executor))
                .limit(nThreads)
                .toArray(genericArray(CompletableFuture[]::new));
        executor.shutdown();
        CompletableFuture.allOf(results).get();  // we're just interested in the exception, if any
    }

    /**
     * Function used to create/cast generic array to expected type. Using this function prevents us from
     * needing a {@code @SuppressWarnings("unchecked")} in the calling code.
     * @param arrayCreator Array constructor lambda taking an integer size parameter and returning array of type T
     * @param <T> The erased type
     * @param <R> The desired type
     * @return Array constructor lambda taking an integer size parameter and returning array of type R
     */
    @SuppressWarnings("unchecked")
    static <T, R extends T> IntFunction<R[]> genericArray(IntFunction<T[]> arrayCreator) {
        return size -> (R[]) arrayCreator.apply(size);
    }

    @Test
    public void parseTransactionWithHugeDeclaredInputsSize() {
        Transaction tx = new HugeDeclaredSizeTransaction(true, false, false);
        byte[] serializedTx = tx.serialize();
        try {
            Transaction.read(ByteBuffer.wrap(serializedTx));
            fail("We expect BufferUnderflowException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (BufferUnderflowException e) {
            //Expected, do nothing
        }
    }

    @Test
    public void parseTransactionWithHugeDeclaredOutputsSize() {
        Transaction tx = new HugeDeclaredSizeTransaction(false, true, false);
        byte[] serializedTx = tx.serialize();
        try {
            Transaction.read(ByteBuffer.wrap(serializedTx));
            fail("We expect BufferUnderflowException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (BufferUnderflowException e) {
            //Expected, do nothing
        }
    }

    @Test
    public void parseTransactionWithHugeDeclaredWitnessPushCountSize() {
        Transaction tx = new HugeDeclaredSizeTransaction(false, false, true);
        byte[] serializedTx = tx.serialize();
        try {
            Transaction.read(ByteBuffer.wrap(serializedTx));
            fail("We expect BufferUnderflowException with the fixed code and OutOfMemoryError with the buggy code, so this is weird");
        } catch (BufferUnderflowException e) {
            //Expected, do nothing
        }
    }

    private static class HugeDeclaredSizeTransaction extends Transaction {

        private boolean hackInputsSize;
        private boolean hackOutputsSize;
        private boolean hackWitnessPushCountSize;

        public HugeDeclaredSizeTransaction(boolean hackInputsSize, boolean hackOutputsSize, boolean hackWitnessPushCountSize) {
            super();
            Transaction inputTx = new Transaction();
            inputTx.addOutput(Coin.FIFTY_COINS, new ECKey());
            this.addInput(inputTx.getOutput(0));
            this.getInput(0).disconnect();
            TransactionWitness witness = TransactionWitness.of(new byte[] { 0 });
            this.getInput(0).setWitness(witness);
            this.addOutput(Coin.COIN, new ECKey());

            this.hackInputsSize = hackInputsSize;
            this.hackOutputsSize = hackOutputsSize;
            this.hackWitnessPushCountSize = hackWitnessPushCountSize;
        }

        @Override
        protected void bitcoinSerializeToStream(OutputStream stream, boolean useSegwit) throws IOException {
            // version
            writeInt32LE(getVersion(), stream);
            // marker, flag
            if (useSegwit) {
                stream.write(0);
                stream.write(1);
            }
            // txin_count, txins
            long inputsSize = hackInputsSize ? Integer.MAX_VALUE : getInputs().size();
            stream.write(VarInt.of(inputsSize).serialize());
            for (TransactionInput in : getInputs())
                stream.write(in.serialize());
            // txout_count, txouts
            long outputsSize = hackOutputsSize ? Integer.MAX_VALUE : getOutputs().size();
            stream.write(VarInt.of(outputsSize).serialize());
            for (TransactionOutput out : getOutputs())
                stream.write(out.serialize());
            // script_witnisses
            if (useSegwit) {
                for (TransactionInput in : getInputs()) {
                    TransactionWitness witness = in.getWitness();
                    long pushCount = hackWitnessPushCountSize ? Integer.MAX_VALUE : witness.getPushCount();
                    stream.write(VarInt.of(pushCount).serialize());
                    for (int i = 0; i < witness.getPushCount(); i++) {
                        byte[] push = witness.getPush(i);
                        stream.write(VarInt.of(push.length).serialize());
                        stream.write(push);
                    }

                    stream.write(in.getWitness().serialize());
                }
            }
            // lock_time
            writeInt32LE(lockTime().rawValue(), stream);
        }
    }

    @Test
    public void getWeightAndVsize() {
        // example from https://en.bitcoin.it/wiki/Weight_units
        String txHex = "0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f85603000000171600141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b928ffffffff019caef505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100f764287d3e99b1474da9bec7f7ed236d6c81e793b20c4b5aa1f3051b9a7daa63022016a198031d5554dbb855bdbe8534776a4be6958bd8d530dc001c32b828f6f0ab0121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac00000000";
        Transaction tx = Transaction.read(ByteBuffer.wrap(ByteUtils.parseHex(txHex)));
        assertEquals(218, tx.messageSize());
        assertEquals(542, tx.getWeight());
        assertEquals(136, tx.getVsize());
    }

    @Test
    public void nonSegwitZeroInputZeroOutputTx() {
        // Non segwit tx with zero input and outputs
        String txHex = "010000000000f1f2f3f4";
        Transaction tx = TESTNET.getDefaultSerializer().makeTransaction(ByteBuffer.wrap(ByteUtils.parseHex(txHex)));
        assertEquals(txHex, ByteUtils.formatHex(tx.serialize()));
    }

    @Test
    public void nonSegwitZeroInputOneOutputTx() {
        // Non segwit tx with zero input and one output that has an amount of `0100000000000000` that could confuse
        // a naive segwit parser. This can only be read with segwit disabled
        MessageSerializer serializer = TESTNET.getDefaultSerializer();
        String txHex = "0100000000010100000000000000016af1f2f3f4";
        int protoVersionNoWitness = serializer.getProtocolVersion() | Transaction.SERIALIZE_TRANSACTION_NO_WITNESS;
        Transaction tx = serializer.withProtocolVersion(protoVersionNoWitness).makeTransaction(ByteBuffer.wrap(ByteUtils.parseHex(txHex)));
        assertEquals(txHex, ByteUtils.formatHex(tx.serialize()));
    }
}
