/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2017 Thomas König
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

package org.bitcoinj.script;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.collect.Lists;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.crypto.DumpedPrivateKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.core.MessageSerializer;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Transaction.SigHash;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script.VerifyFlag;
import org.hamcrest.core.IsNot;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.bitcoinj.core.Transaction.SERIALIZE_TRANSACTION_NO_WITNESS;
import static org.bitcoinj.script.ScriptOpCodes.OP_0;
import static org.bitcoinj.script.ScriptOpCodes.OP_INVALIDOPCODE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ScriptTest {
    // From tx 05e04c26c12fe408a3c1b71aa7996403f6acad1045252b1c62e055496f4d2cb1 on the testnet.

    private static final String sigProg = "47304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c";

    private static final String pubkeyProg = "76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac";

    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private static final Logger log = LoggerFactory.getLogger(ScriptTest.class);

    @Test
    public void testScriptSig() {
        byte[] sigProgBytes = ByteUtils.parseHex(sigProg);
        Script script = Script.parse(sigProgBytes);
        assertEquals(
                "PUSHDATA(71)[304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701] PUSHDATA(65)[0414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c]",
                script.toString());
    }

    @Test
    public void testScriptPubKey() {
        // Check we can extract the to address
        byte[] pubkeyBytes = ByteUtils.parseHex(pubkeyProg);
        Script pubkey = Script.parse(pubkeyBytes);
        assertEquals("DUP HASH160 PUSHDATA(20)[33e81a941e64cda12c6a299ed322ddbdd03f8d0e] EQUALVERIFY CHECKSIG", pubkey.toString());
        Address toAddr = LegacyAddress.fromPubKeyHash(BitcoinNetwork.TESTNET, ScriptPattern.extractHashFromP2PKH(pubkey));
        assertEquals("mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2", toAddr.toString());
    }

    @Test
    public void testMultiSig() {
        List<ECKey> keys = Lists.newArrayList(ECKey.random(), ECKey.random(), ECKey.random());
        assertTrue(ScriptPattern.isSentToMultisig(ScriptBuilder.createMultiSigOutputScript(2, keys)));
        Script script = ScriptBuilder.createMultiSigOutputScript(3, keys);
        assertTrue(ScriptPattern.isSentToMultisig(script));
        List<ECKey> pubkeys = new ArrayList<>(3);
        for (ECKey key : keys) pubkeys.add(ECKey.fromPublicOnly(key));
        assertEquals(script.getPubKeys(), pubkeys);
        assertFalse(ScriptPattern.isSentToMultisig(ScriptBuilder.createP2PKOutputScript(ECKey.random())));
        try {
            // Fail if we ask for more signatures than keys.
            Script.createMultiSigOutputScript(4, keys);
            fail();
        } catch (Throwable e) {
            // Expected.
        }
        try {
            // Must have at least one signature required.
            Script.createMultiSigOutputScript(0, keys);
        } catch (Throwable e) {
            // Expected.
        }
        // Actual execution is tested by the data driven tests.
    }

    @Test
    public void testP2SHOutputScript() {
        Address p2shAddress = LegacyAddress.fromBase58("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU", BitcoinNetwork.MAINNET);
        assertTrue(ScriptPattern.isP2SH(ScriptBuilder.createOutputScript(p2shAddress)));
    }

    @Test
    public void testIp() {
        byte[] bytes = ByteUtils.parseHex("41043e96222332ea7848323c08116dddafbfa917b8e37f0bdf63841628267148588a09a43540942d58d49717ad3fabfe14978cf4f0a8b84d2435dad16e9aa4d7f935ac");
        Script s = Script.parse(bytes);
        assertTrue(ScriptPattern.isP2PK(s));
    }
    
    @Test
    public void testCreateMultiSigInputScript() {
        // Setup transaction and signatures
        ECKey key1 = DumpedPrivateKey.fromBase58(BitcoinNetwork.TESTNET, "cVLwRLTvz3BxDAWkvS3yzT9pUcTCup7kQnfT2smRjvmmm1wAP6QT").getKey();
        ECKey key2 = DumpedPrivateKey.fromBase58(BitcoinNetwork.TESTNET, "cTine92s8GLpVqvebi8rYce3FrUYq78ZGQffBYCS1HmDPJdSTxUo").getKey();
        ECKey key3 = DumpedPrivateKey.fromBase58(BitcoinNetwork.TESTNET, "cVHwXSPRZmL9adctwBwmn4oTZdZMbaCsR5XF6VznqMgcvt1FDDxg").getKey();
        Script multisigScript = ScriptBuilder.createMultiSigOutputScript(2, Arrays.asList(key1, key2, key3));
        byte[] bytes = ByteUtils.parseHex("01000000013df681ff83b43b6585fa32dd0e12b0b502e6481e04ee52ff0fdaf55a16a4ef61000000006b483045022100a84acca7906c13c5895a1314c165d33621cdcf8696145080895cbf301119b7cf0220730ff511106aa0e0a8570ff00ee57d7a6f24e30f592a10cae1deffac9e13b990012102b8d567bcd6328fd48a429f9cf4b315b859a58fd28c5088ef3cb1d98125fc4e8dffffffff02364f1c00000000001976a91439a02793b418de8ec748dd75382656453dc99bcb88ac40420f000000000017a9145780b80be32e117f675d6e0ada13ba799bf248e98700000000");
        Transaction transaction = TESTNET.getDefaultSerializer().makeTransaction(ByteBuffer.wrap(bytes));
        TransactionOutput output = transaction.getOutput(1);
        Transaction spendTx = new Transaction();
        Address address = LegacyAddress.fromBase58("n3CFiCmBXVt5d3HXKQ15EFZyhPz4yj5F3H", BitcoinNetwork.TESTNET);
        Script outputScript = ScriptBuilder.createOutputScript(address);
        spendTx.addOutput(output.getValue(), outputScript);
        spendTx.addInput(output);
        Sha256Hash sighash = spendTx.hashForSignature(0, multisigScript, SigHash.ALL, false);
        ECKey.ECDSASignature party1Signature = key1.sign(sighash);
        ECKey.ECDSASignature party2Signature = key2.sign(sighash);
        TransactionSignature party1TransactionSignature = new TransactionSignature(party1Signature, SigHash.ALL, false);
        TransactionSignature party2TransactionSignature = new TransactionSignature(party2Signature, SigHash.ALL, false);

        // Create p2sh multisig input script
        Script inputScript = ScriptBuilder.createP2SHMultiSigInputScript(Arrays.asList(party1TransactionSignature, party2TransactionSignature), multisigScript);

        // Assert that the input script contains 4 chunks
        assertTrue(inputScript.chunks().size() == 4);

        // Assert that the input script created contains the original multisig
        // script as the last chunk
        ScriptChunk scriptChunk = inputScript.chunks().get(inputScript.chunks().size() - 1);
        assertArrayEquals(scriptChunk.data, multisigScript.program());

        // Create regular multisig input script
        inputScript = ScriptBuilder.createMultiSigInputScript(Arrays.asList(party1TransactionSignature, party2TransactionSignature));

        // Assert that the input script only contains 3 chunks
        assertTrue(inputScript.chunks().size() == 3);

        // Assert that the input script created does not end with the original
        // multisig script
        scriptChunk = inputScript.chunks().get(inputScript.chunks().size() - 1);
        assertThat(scriptChunk.data, IsNot.not(equalTo(multisigScript.program())));
    }

    @Test
    public void createAndUpdateEmptyInputScript() {
        TransactionSignature dummySig = TransactionSignature.dummy();
        ECKey key = ECKey.random();

        // P2PK
        Script inputScript = ScriptBuilder.createInputScript(dummySig);
        assertThat(inputScript.chunks().get(0).data, equalTo(dummySig.encodeToBitcoin()));
        inputScript = ScriptBuilder.createInputScript(null);
        assertThat(inputScript.chunks().get(0).opcode, equalTo(OP_0));

        // P2PKH
        inputScript = ScriptBuilder.createInputScript(dummySig, key);
        assertThat(inputScript.chunks().get(0).data, equalTo(dummySig.encodeToBitcoin()));
        inputScript = ScriptBuilder.createInputScript(null, key);
        assertThat(inputScript.chunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.chunks().get(1).data, equalTo(key.getPubKey()));

        // P2SH
        ECKey key2 = ECKey.random();
        Script multisigScript = ScriptBuilder.createMultiSigOutputScript(2, Arrays.asList(key, key2));
        inputScript = ScriptBuilder.createP2SHMultiSigInputScript(Arrays.asList(dummySig, dummySig), multisigScript);
        assertThat(inputScript.chunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.chunks().get(1).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.chunks().get(2).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.chunks().get(3).data, equalTo(multisigScript.program()));

        inputScript = ScriptBuilder.createP2SHMultiSigInputScript(null, multisigScript);
        assertThat(inputScript.chunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.chunks().get(1).opcode, equalTo(OP_0));
        assertThat(inputScript.chunks().get(2).opcode, equalTo(OP_0));
        assertThat(inputScript.chunks().get(3).data, equalTo(multisigScript.program()));

        inputScript = ScriptBuilder.updateScriptWithSignature(inputScript, dummySig.encodeToBitcoin(), 0, 1, 1);
        assertThat(inputScript.chunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.chunks().get(1).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.chunks().get(2).opcode, equalTo(OP_0));
        assertThat(inputScript.chunks().get(3).data, equalTo(multisigScript.program()));

        inputScript = ScriptBuilder.updateScriptWithSignature(inputScript, dummySig.encodeToBitcoin(), 1, 1, 1);
        assertThat(inputScript.chunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.chunks().get(1).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.chunks().get(2).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.chunks().get(3).data, equalTo(multisigScript.program()));

        // updating scriptSig with no missing signatures
        try {
            ScriptBuilder.updateScriptWithSignature(inputScript, dummySig.encodeToBitcoin(), 1, 1, 1);
            fail("Exception expected");
        } catch (Exception e) {
            assertEquals(IllegalArgumentException.class, e.getClass());
        }
    }

    @Test
    public void testOp0() {
        // Check that OP_0 doesn't NPE and pushes an empty stack frame.
        Transaction tx = new Transaction();
        tx.addInput(new TransactionInput(tx, new byte[0], TransactionOutPoint.UNCONNECTED));
        Script script = new ScriptBuilder().smallNum(0).build();

        LinkedList<byte[]> stack = new LinkedList<>();
        Script.executeScript(tx, 0, script, stack, Script.ALL_VERIFY_FLAGS);
        assertEquals("OP_0 push length", 0, stack.get(0).length);
    }

    private Script parseScriptString(String string) throws IOException {
        String[] words = string.split("[ \\t\\n]");
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for(String w : words) {
            if (w.equals(""))
                continue;
            if (w.matches("^-?[0-9]*$")) {
                // Number
                long val = Long.parseLong(w);
                if (val >= -1 && val <= 16)
                    out.write(Script.encodeToOpN((int)val));
                else
                    Script.writeBytes(out, ByteUtils.reverseBytes(ByteUtils.encodeMPI(BigInteger.valueOf(val), false)));
            } else if (w.matches("^0x[0-9a-fA-F]*$")) {
                // Raw hex data, inserted NOT pushed onto stack:
                out.write(ByteUtils.parseHex(w.substring(2).toLowerCase()));
            } else if (w.length() >= 2 && w.startsWith("'") && w.endsWith("'")) {
                // Single-quoted string, pushed as data. NOTE: this is poor-man's
                // parsing, spaces/tabs/newlines in single-quoted strings won't work.
                Script.writeBytes(out, w.substring(1, w.length() - 1).getBytes(StandardCharsets.UTF_8));
            } else if (ScriptOpCodes.getOpCode(w) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w));
            } else if (w.startsWith("OP_") && ScriptOpCodes.getOpCode(w.substring(3)) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w.substring(3)));
            } else {
                throw new RuntimeException("Invalid word: '" + w + "'");
            }                        
        }
        
        return Script.parse(out.toByteArray());
    }

    private Set<VerifyFlag> parseVerifyFlags(String str) {
        Set<VerifyFlag> flags = EnumSet.noneOf(VerifyFlag.class);
        if (!"NONE".equals(str)) {
            for (String flag : str.split(",")) {
                try {
                    flags.add(VerifyFlag.valueOf(flag));
                } catch (IllegalArgumentException x) {
                    log.debug("Cannot handle verify flag {} -- ignored.", flag);
                }
            }
        }
        return flags;
    }

    @Test
    public void dataDrivenScripts() throws Exception {
        List<List<String>> tests = readScriptTestsJson("script_tests.json");
        for (List<String> test : tests) {
            Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2));
            ScriptError expectedError = ScriptError.fromMnemonic(test.get(3));
            try {
                Script scriptSig = parseScriptString(test.get(0));
                Script scriptPubKey = parseScriptString(test.get(1));
                Transaction txCredit = buildCreditingTransaction(scriptPubKey);
                Transaction txSpend = buildSpendingTransaction(txCredit, scriptSig);
                scriptSig.correctlySpends(txSpend, 0, null, null, scriptPubKey, verifyFlags);
                if (!expectedError.equals(ScriptError.SCRIPT_ERR_OK))
                    fail(test + " is expected to fail");
            } catch (ScriptException e) {
                if (!e.getError().equals(expectedError)) {
                    System.err.println(test);
                    e.printStackTrace();
                    System.err.flush();
                    throw e;
                }
            }
        }
    }

    private Map<TransactionOutPoint, Script> parseScriptPubKeys(List<ScriptPubKeyEntry> inputs) throws IOException {
        Map<TransactionOutPoint, Script> scriptPubKeys = new HashMap<>();
        for (ScriptPubKeyEntry input : inputs) {
            String hash = input.hash;
            long index = input.index;
            if (index == -1)
                index = ByteUtils.MAX_UNSIGNED_INTEGER;
            String script = input.script;
            Sha256Hash sha256Hash = Sha256Hash.wrap(ByteUtils.parseHex(hash));
            scriptPubKeys.put(TransactionOutPoint.of(sha256Hash, index), parseScriptString(script));
        }
        return scriptPubKeys;
    }

    private Transaction buildCreditingTransaction(Script scriptPubKey) {
        Transaction tx = new Transaction();
        tx.setVersion(1);
        tx.setLockTime(0);

        TransactionInput txInput = new TransactionInput(null,
                new ScriptBuilder().number(0).number(0).build().program(), TransactionOutPoint.UNCONNECTED);
        txInput = txInput.withSequence(TransactionInput.NO_SEQUENCE);
        tx.addInput(txInput);

        TransactionOutput txOutput = new TransactionOutput(tx, Coin.ZERO, scriptPubKey.program());
        tx.addOutput(txOutput);

        return tx;
    }

    private Transaction buildSpendingTransaction(Transaction creditingTransaction, Script scriptSig) {
        Transaction tx = new Transaction();
        tx.setVersion(1);
        tx.setLockTime(0);

        TransactionInput txInput = new TransactionInput(creditingTransaction, scriptSig.program(),
                TransactionOutPoint.UNCONNECTED);
        txInput = txInput.withSequence(TransactionInput.NO_SEQUENCE);
        tx.addInput(txInput);

        TransactionOutput txOutput = new TransactionOutput(tx, creditingTransaction.getOutput(0).getValue(),
                Script.parse(new byte[] {}).program());
        tx.addOutput(txOutput);

        return tx;
    }

    @Test
    public void dataDrivenValidTransactions() throws Exception {
        List<TestEntry> tests = readTransactionsJson("tx_valid.json");
        for (TestEntry test : tests) {
            Transaction transaction = null;
            try {
                Map<TransactionOutPoint, Script> scriptPubKeys = parseScriptPubKeys(test.scriptPubKeyEntries);
                transaction = TESTNET.getDefaultSerializer().makeTransaction(ByteBuffer.wrap(ByteUtils.parseHex(test.transaction.toLowerCase())));
                Transaction.verify(TESTNET.network(), transaction);
                Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.verifyFlags);

                for (int i = 0; i < transaction.getInputs().size(); i++) {
                    TransactionInput input = transaction.getInput(i);
                    assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
                    input.getScriptSig().correctlySpends(transaction, i, null, null,
                            scriptPubKeys.get(input.getOutpoint()), verifyFlags);
                }
            } catch (Exception e) {
                System.err.println(test);
                if (transaction != null)
                    System.err.println(transaction);
                throw e;
            }
        }
    }

    @Test
    public void dataDrivenInvalidTransactions() throws Exception {
        List<TestEntry> tests = readTransactionsJson("tx_invalid.json");
        for (TestEntry test : tests) {
            Map<TransactionOutPoint, Script> scriptPubKeys = parseScriptPubKeys(test.scriptPubKeyEntries);
            byte[] txBytes = ByteUtils.parseHex(test.transaction.toLowerCase());
            MessageSerializer serializer = TESTNET.getDefaultSerializer();
            Transaction transaction;
            try {
                transaction = serializer.makeTransaction(ByteBuffer.wrap(txBytes));
            } catch (ProtocolException ignore) {
                // Try to parse as a no-witness transaction because some vectors are 0-input, 1-output txs that fail
                // to correctly parse as witness transactions.
                int protoVersionNoWitness = serializer.getProtocolVersion() | SERIALIZE_TRANSACTION_NO_WITNESS;
                transaction = serializer.withProtocolVersion(protoVersionNoWitness).makeTransaction(ByteBuffer.wrap(txBytes));
            }
            Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.verifyFlags);

            boolean valid = true;
            try {
                Transaction.verify(TESTNET.network(), transaction);
            } catch (VerificationException e) {
                valid = false;
            }

            // Bitcoin Core checks this case in CheckTransaction, but we leave it to
            // later where we will see an attempt to double-spend, so we explicitly check here
            HashSet<TransactionOutPoint> set = new HashSet<>();
            for (TransactionInput input : transaction.getInputs()) {
                if (set.contains(input.getOutpoint()))
                    valid = false;
                set.add(input.getOutpoint());
            }

            for (int i = 0; i < transaction.getInputs().size() && valid; i++) {
                TransactionInput input = transaction.getInput(i);
                assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
                try {
                    input.getScriptSig().correctlySpends(transaction, i, null, null,
                            scriptPubKeys.get(input.getOutpoint()), verifyFlags);
                } catch (VerificationException e) {
                    valid = false;
                }
            }

            if (valid) {
                System.out.println(test);
                fail();
            }
        }
    }

    @Test
    public void getToAddress() {
        // P2PK
        ECKey toKey = ECKey.random();
        Address toAddress = toKey.toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        assertEquals(toAddress, ScriptBuilder.createP2PKOutputScript(toKey).getToAddress(BitcoinNetwork.TESTNET, true));
        // pay to pubkey hash
        assertEquals(toAddress, ScriptBuilder.createOutputScript(toAddress).getToAddress(BitcoinNetwork.TESTNET));
        // pay to script hash
        Script p2shScript = ScriptBuilder.createP2SHOutputScript(new byte[20]);
        Address scriptAddress = LegacyAddress.fromScriptHash(BitcoinNetwork.TESTNET,
                ScriptPattern.extractHashFromP2SH(p2shScript));
        assertEquals(scriptAddress, p2shScript.getToAddress(BitcoinNetwork.TESTNET));
        // P2WPKH
        toAddress = toKey.toAddress(ScriptType.P2WPKH, BitcoinNetwork.TESTNET);
        assertEquals(toAddress, ScriptBuilder.createOutputScript(toAddress).getToAddress(BitcoinNetwork.TESTNET));
        // P2WSH
        Script p2wshScript = ScriptBuilder.createP2WSHOutputScript(new byte[32]);
        scriptAddress = SegwitAddress.fromHash(BitcoinNetwork.TESTNET, ScriptPattern.extractHashFromP2WH(p2wshScript));
        assertEquals(scriptAddress, p2wshScript.getToAddress(BitcoinNetwork.TESTNET));
        // P2TR
        toAddress = SegwitAddress.fromProgram(BitcoinNetwork.TESTNET, 1, new byte[32]);
        assertEquals(toAddress, ScriptBuilder.createOutputScript(toAddress).getToAddress(BitcoinNetwork.TESTNET));
    }

    @Test(expected = ScriptException.class)
    public void getToAddressNoPubKey() {
        ScriptBuilder.createP2PKOutputScript(ECKey.random()).getToAddress(BitcoinNetwork.TESTNET, false);
    }

    List<List<String>> readScriptTestsJson(String resourcePath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JavaType type = mapper.getTypeFactory().constructCollectionType(List.class, mapper.getTypeFactory()
                .constructCollectionType(List.class, String.class));
        List<List<String>> list = mapper.readValue(getClass().getResourceAsStream(resourcePath), type);
        return list.stream()
                .filter(test -> test.size() > 1)    // Filter out comment entries
                .collect(Collectors.toList());
    }

    List<TestEntry> readTransactionsJson(String resourcePath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JavaType type = mapper.getTypeFactory().constructCollectionType(List.class, JsonNode.class);
        List<JsonNode> nodes = mapper.readValue(getClass().getResourceAsStream(resourcePath), type);
        return  nodes.stream()
                .filter(test -> !(test.isArray() && test.size() == 1 && test.get(0).isTextual()))
                .map(n -> mapper.convertValue(n, TestEntry.class))
                .collect(Collectors.toList());
    }

    @Test
    public void checkTestEntryToString() throws JsonProcessingException {
        String expectedOutput = "[ [ [ \"0000000000000000000000000000000000000000000000000000000000000100\", 0, \"HASH160 0x14 0xb558cbf4930954aa6a344363a15668d7477ae716 EQUAL\" ] ], " +
                "\"01000000010001000000000000000000000000000000000000000000000000000000000000000000006d483045022027deccc14aa6668e78a8c9da3484fbcd4f9dcc9bb7d1b85146314b21b9ae4d86022100d0b43dece8cfb07348de0ca8bc5b86276fa88f7f2138381128b7c36ab2e42264012321029bb13463ddd5d2cc05da6e84e37536cb9525703cfd8f43afdb414988987a92f6acffffffff020040075af075070001510000000000000000015100000000\", \"P2SH\" ]";
        ObjectMapper mapper = new ObjectMapper();
        TestEntry entry = mapper.readValue(expectedOutput, TestEntry.class);
        assertEquals(expectedOutput, entry.toString());
    }

    @Test
    public void checkScriptPubKeyEntryToString() {
        ScriptPubKeyEntry entry = new ScriptPubKeyEntry(Sha256Hash.ZERO_HASH.toString(), 1, "HASH160");
        String expectedOutput = "[ \"0000000000000000000000000000000000000000000000000000000000000000\", 1, \"HASH160\" ]";
        assertEquals(expectedOutput, entry.toString());
    }

    @JsonSerialize(using = TestEntry.Serializer.class)
    static class TestEntry {
        public final List<ScriptPubKeyEntry> scriptPubKeyEntries;
        public final String transaction;
        public final String verifyFlags;

        @JsonCreator
        public TestEntry(List<Object> entry) {
            this((List<List<Object>>) entry.get(0), (String) entry.get(1), (String) entry.get(2));
        }

        TestEntry(List<List<Object>> scriptPubKeyEntries, String transaction, String verifyFlags) {
            this.scriptPubKeyEntries = scriptPubKeyEntries.stream()
                    .map(l -> new ScriptPubKeyEntry((String) l.get(0), (int) l.get(1), (String) l.get(2)))
                    .collect(Collectors.toList());
            this.transaction = transaction;
            this.verifyFlags = verifyFlags;
        }

        @Override
        public String toString() {
            ObjectWriter writer = new ObjectMapper().writerWithDefaultPrettyPrinter();
            try {
                return writer.writeValueAsString(this);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        static class Serializer extends JsonSerializer<TestEntry> {
            @Override
            public void serialize(TestEntry value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
                gen.writeStartArray();
                gen.writeStartArray();
                for (ScriptPubKeyEntry entry : value.scriptPubKeyEntries) {
                    gen.writeObject(entry);
                }
                gen.writeEndArray();
                gen.writeString(value.transaction);
                gen.writeString(value.verifyFlags);
                gen.writeEndArray();
            }
        }
    }

    @JsonSerialize(using = ScriptPubKeyEntry.Serializer.class)
    static class ScriptPubKeyEntry {
        public final String hash;
        public final long index;
        public final String script;

        public ScriptPubKeyEntry(String hash, long index, String script) {
            this.hash = hash;
            this.index = index;
            this.script = script;
        }

        @Override
        public String toString() {
            ObjectWriter writer = new ObjectMapper().writerWithDefaultPrettyPrinter();
            try {
                return writer.writeValueAsString(this);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        static class Serializer extends JsonSerializer<ScriptPubKeyEntry> {
            @Override
            public void serialize(ScriptPubKeyEntry value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
                gen.writeStartArray();
                gen.writeString(value.hash);
                gen.writeNumber(value.index);
                gen.writeString(value.script);
                gen.writeEndArray();
            }
        }
    }
}
