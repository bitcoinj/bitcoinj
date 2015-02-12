/**
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

package org.bitcoinj.script;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bitcoinj.core.*;
import org.bitcoinj.core.Transaction.SigHash;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script.VerifyFlag;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import org.hamcrest.core.IsNot;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.*;

import static org.bitcoinj.core.Utils.HEX;
import static org.bitcoinj.script.ScriptOpCodes.OP_0;
import static org.bitcoinj.script.ScriptOpCodes.OP_INVALIDOPCODE;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.*;

public class ScriptTest {
    // From tx 05e04c26c12fe408a3c1b71aa7996403f6acad1045252b1c62e055496f4d2cb1 on the testnet.

    static final String sigProg = "47304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c";

    static final String pubkeyProg = "76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac";

    static final NetworkParameters params = TestNet3Params.get();

    private static final Logger log = LoggerFactory.getLogger(ScriptTest.class);

    @Test
    public void testScriptSig() throws Exception {
        byte[] sigProgBytes = HEX.decode(sigProg);
        Script script = new Script(sigProgBytes);
        // Test we can extract the from address.
        byte[] hash160 = Utils.sha256hash160(script.getPubKey());
        Address a = new Address(params, hash160);
        assertEquals("mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2", a.toString());
    }

    @Test
    public void testScriptPubKey() throws Exception {
        // Check we can extract the to address
        byte[] pubkeyBytes = HEX.decode(pubkeyProg);
        Script pubkey = new Script(pubkeyBytes);
        assertEquals("DUP HASH160 PUSHDATA(20)[33e81a941e64cda12c6a299ed322ddbdd03f8d0e] EQUALVERIFY CHECKSIG", pubkey.toString());
        Address toAddr = new Address(params, pubkey.getPubKeyHash());
        assertEquals("mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2", toAddr.toString());
    }

    @Test
    public void testMultiSig() throws Exception {
        List<ECKey> keys = Lists.newArrayList(new ECKey(), new ECKey(), new ECKey());
        assertTrue(ScriptBuilder.createMultiSigOutputScript(2, keys).isSentToMultiSig());
        assertTrue(ScriptBuilder.createMultiSigOutputScript(3, keys).isSentToMultiSig());
        assertFalse(ScriptBuilder.createOutputScript(new ECKey()).isSentToMultiSig());
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
    public void testP2SHOutputScript() throws Exception {
      Address p2shAddress = new Address(MainNetParams.get(), "35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU");
      assertTrue(ScriptBuilder.createOutputScript(p2shAddress).isPayToScriptHash());
    }

    @Test
    public void testIp() throws Exception {
        byte[] bytes = HEX.decode("41043e96222332ea7848323c08116dddafbfa917b8e37f0bdf63841628267148588a09a43540942d58d49717ad3fabfe14978cf4f0a8b84d2435dad16e9aa4d7f935ac");
        Script s = new Script(bytes);
        assertTrue(s.isSentToRawPubKey());
    }
    
    @Test
    public void testCreateMultiSigInputScript() throws AddressFormatException {
        // Setup transaction and signatures
        ECKey key1 = new DumpedPrivateKey(params, "cVLwRLTvz3BxDAWkvS3yzT9pUcTCup7kQnfT2smRjvmmm1wAP6QT").getKey();
        ECKey key2 = new DumpedPrivateKey(params, "cTine92s8GLpVqvebi8rYce3FrUYq78ZGQffBYCS1HmDPJdSTxUo").getKey();
        ECKey key3 = new DumpedPrivateKey(params, "cVHwXSPRZmL9adctwBwmn4oTZdZMbaCsR5XF6VznqMgcvt1FDDxg").getKey();
        Script multisigScript = ScriptBuilder.createMultiSigOutputScript(2, Arrays.asList(key1, key2, key3));
        byte[] bytes = HEX.decode("01000000013df681ff83b43b6585fa32dd0e12b0b502e6481e04ee52ff0fdaf55a16a4ef61000000006b483045022100a84acca7906c13c5895a1314c165d33621cdcf8696145080895cbf301119b7cf0220730ff511106aa0e0a8570ff00ee57d7a6f24e30f592a10cae1deffac9e13b990012102b8d567bcd6328fd48a429f9cf4b315b859a58fd28c5088ef3cb1d98125fc4e8dffffffff02364f1c00000000001976a91439a02793b418de8ec748dd75382656453dc99bcb88ac40420f000000000017a9145780b80be32e117f675d6e0ada13ba799bf248e98700000000");
        Transaction transaction = new Transaction(params, bytes);
        TransactionOutput output = transaction.getOutput(1);
        Transaction spendTx = new Transaction(params);
        Address address = new Address(params, "n3CFiCmBXVt5d3HXKQ15EFZyhPz4yj5F3H");
        Script outputScript = ScriptBuilder.createOutputScript(address);
        spendTx.addOutput(output.getValue(), outputScript);
        spendTx.addInput(output);
        Sha256Hash sighash = spendTx.hashForSignature(0, multisigScript, SigHash.ALL, false);
        ECKey.ECDSASignature party1Signature = key1.sign(sighash);
        ECKey.ECDSASignature party2Signature = key2.sign(sighash);
        TransactionSignature party1TransactionSignature = new TransactionSignature(party1Signature, SigHash.ALL, false);
        TransactionSignature party2TransactionSignature = new TransactionSignature(party2Signature, SigHash.ALL, false);

        // Create p2sh multisig input script
        Script inputScript = ScriptBuilder.createP2SHMultiSigInputScript(ImmutableList.of(party1TransactionSignature, party2TransactionSignature), multisigScript);

        // Assert that the input script contains 4 chunks
        assertTrue(inputScript.getChunks().size() == 4);

        // Assert that the input script created contains the original multisig
        // script as the last chunk
        ScriptChunk scriptChunk = inputScript.getChunks().get(inputScript.getChunks().size() - 1);
        Assert.assertArrayEquals(scriptChunk.data, multisigScript.getProgram());

        // Create regular multisig input script
        inputScript = ScriptBuilder.createMultiSigInputScript(ImmutableList.of(party1TransactionSignature, party2TransactionSignature));

        // Assert that the input script only contains 3 chunks
        assertTrue(inputScript.getChunks().size() == 3);

        // Assert that the input script created does not end with the original
        // multisig script
        scriptChunk = inputScript.getChunks().get(inputScript.getChunks().size() - 1);
        Assert.assertThat(scriptChunk.data, IsNot.not(equalTo(multisigScript.getProgram())));
    }

    @Test
    public void createAndUpdateEmptyInputScript() throws Exception {
        TransactionSignature dummySig = TransactionSignature.dummy();
        ECKey key = new ECKey();

        // pay-to-pubkey
        Script inputScript = ScriptBuilder.createInputScript(dummySig);
        assertThat(inputScript.getChunks().get(0).data, equalTo(dummySig.encodeToBitcoin()));
        inputScript = ScriptBuilder.createInputScript(null);
        assertThat(inputScript.getChunks().get(0).opcode, equalTo(OP_0));

        // pay-to-address
        inputScript = ScriptBuilder.createInputScript(dummySig, key);
        assertThat(inputScript.getChunks().get(0).data, equalTo(dummySig.encodeToBitcoin()));
        inputScript = ScriptBuilder.createInputScript(null, key);
        assertThat(inputScript.getChunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.getChunks().get(1).data, equalTo(key.getPubKey()));

        // pay-to-script-hash
        ECKey key2 = new ECKey();
        Script multisigScript = ScriptBuilder.createMultiSigOutputScript(2, Arrays.asList(key, key2));
        inputScript = ScriptBuilder.createP2SHMultiSigInputScript(Arrays.asList(dummySig, dummySig), multisigScript);
        assertThat(inputScript.getChunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.getChunks().get(1).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.getChunks().get(2).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.getChunks().get(3).data, equalTo(multisigScript.getProgram()));

        inputScript = ScriptBuilder.createP2SHMultiSigInputScript(null, multisigScript);
        assertThat(inputScript.getChunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.getChunks().get(1).opcode, equalTo(OP_0));
        assertThat(inputScript.getChunks().get(2).opcode, equalTo(OP_0));
        assertThat(inputScript.getChunks().get(3).data, equalTo(multisigScript.getProgram()));

        inputScript = ScriptBuilder.updateScriptWithSignature(inputScript, dummySig.encodeToBitcoin(), 0, 1, 1);
        assertThat(inputScript.getChunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.getChunks().get(1).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.getChunks().get(2).opcode, equalTo(OP_0));
        assertThat(inputScript.getChunks().get(3).data, equalTo(multisigScript.getProgram()));

        inputScript = ScriptBuilder.updateScriptWithSignature(inputScript, dummySig.encodeToBitcoin(), 1, 1, 1);
        assertThat(inputScript.getChunks().get(0).opcode, equalTo(OP_0));
        assertThat(inputScript.getChunks().get(1).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.getChunks().get(2).data, equalTo(dummySig.encodeToBitcoin()));
        assertThat(inputScript.getChunks().get(3).data, equalTo(multisigScript.getProgram()));

        // updating scriptSig with no missing signatures
        try {
            ScriptBuilder.updateScriptWithSignature(inputScript, dummySig.encodeToBitcoin(), 1, 1, 1);
            fail("Exception expected");
        } catch (Exception e) {
            assertEquals(IllegalArgumentException.class, e.getClass());
        }
    }

    private Script parseScriptString(String string) throws IOException {
        String[] words = string.split("[ \\t\\n]");
        
        UnsafeByteArrayOutputStream out = new UnsafeByteArrayOutputStream();

        for(String w : words) {
            if (w.equals(""))
                continue;
            if (w.matches("^-?[0-9]*$")) {
                // Number
                long val = Long.parseLong(w);
                if (val >= -1 && val <= 16)
                    out.write(Script.encodeToOpN((int)val));
                else
                    Script.writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(val), false)));
            } else if (w.matches("^0x[0-9a-fA-F]*$")) {
                // Raw hex data, inserted NOT pushed onto stack:
                out.write(HEX.decode(w.substring(2).toLowerCase()));
            } else if (w.length() >= 2 && w.startsWith("'") && w.endsWith("'")) {
                // Single-quoted string, pushed as data. NOTE: this is poor-man's
                // parsing, spaces/tabs/newlines in single-quoted strings won't work.
                Script.writeBytes(out, w.substring(1, w.length() - 1).getBytes(Charset.forName("UTF-8")));
            } else if (ScriptOpCodes.getOpCode(w) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w));
            } else if (w.startsWith("OP_") && ScriptOpCodes.getOpCode(w.substring(3)) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w.substring(3)));
            } else {
                throw new RuntimeException("Invalid Data");
            }                        
        }
        
        return new Script(out.toByteArray());
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
    public void dataDrivenValidScripts() throws Exception {
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
                "script_valid.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            Script scriptSig = parseScriptString(test.get(0).asText());
            Script scriptPubKey = parseScriptString(test.get(1).asText());
            Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());
            try {
                scriptSig.correctlySpends(new Transaction(params), 0, scriptPubKey, verifyFlags);
            } catch (ScriptException e) {
                System.err.println(test);
                System.err.flush();
                throw e;
            }
        }
    }
    
    @Test
    public void dataDrivenInvalidScripts() throws Exception {
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
                "script_invalid.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            try {
                Script scriptSig = parseScriptString(test.get(0).asText());
                Script scriptPubKey = parseScriptString(test.get(1).asText());
                Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());
                scriptSig.correctlySpends(new Transaction(params), 0, scriptPubKey, verifyFlags);
                System.err.println(test);
                System.err.flush();
                fail();
            } catch (VerificationException e) {
                // Expected.
            }
        }
    }
    
    private Map<TransactionOutPoint, Script> parseScriptPubKeys(JsonNode inputs) throws IOException {
        Map<TransactionOutPoint, Script> scriptPubKeys = new HashMap<TransactionOutPoint, Script>();
        for (JsonNode input : inputs) {
            String hash = input.get(0).asText();
            int index = input.get(1).asInt();
            String script = input.get(2).asText();
            Sha256Hash sha256Hash = new Sha256Hash(HEX.decode(hash));
            scriptPubKeys.put(new TransactionOutPoint(params, index, sha256Hash), parseScriptString(script));
        }
        return scriptPubKeys;
    }

    @Test
    public void dataDrivenValidTransactions() throws Exception {
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
                "tx_valid.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            if (test.isArray() && test.size() == 1 && test.get(0).isTextual())
                continue; // This is a comment.
            Transaction transaction = null;
            try {
                Map<TransactionOutPoint, Script> scriptPubKeys = parseScriptPubKeys(test.get(0));
                transaction = new Transaction(params, HEX.decode(test.get(1).asText().toLowerCase()));
                transaction.verify();
                Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());

                for (int i = 0; i < transaction.getInputs().size(); i++) {
                    TransactionInput input = transaction.getInputs().get(i);
                    if (input.getOutpoint().getIndex() == 0xffffffffL)
                        input.getOutpoint().setIndex(-1);
                    assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
                    input.getScriptSig().correctlySpends(transaction, i, scriptPubKeys.get(input.getOutpoint()),
                            verifyFlags);
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
        JsonNode json = new ObjectMapper().readTree(new InputStreamReader(getClass().getResourceAsStream(
                "tx_invalid.json"), Charsets.UTF_8));
        for (JsonNode test : json) {
            if (test.isArray() && test.size() == 1 && test.get(0).isTextual())
                continue; // This is a comment.
            Map<TransactionOutPoint, Script> scriptPubKeys = parseScriptPubKeys(test.get(0));
            Transaction transaction = new Transaction(params, HEX.decode(test.get(1).asText().toLowerCase()));
            Set<VerifyFlag> verifyFlags = parseVerifyFlags(test.get(2).asText());

            boolean valid = true;
            try {
                transaction.verify();
            } catch (VerificationException e) {
                valid = false;
            }

            // The reference client checks this case in CheckTransaction, but we leave it to
            // later where we will see an attempt to double-spend, so we explicitly check here
            HashSet<TransactionOutPoint> set = new HashSet<TransactionOutPoint>();
            for (TransactionInput input : transaction.getInputs()) {
                if (set.contains(input.getOutpoint()))
                    valid = false;
                set.add(input.getOutpoint());
            }

            for (int i = 0; i < transaction.getInputs().size() && valid; i++) {
                TransactionInput input = transaction.getInputs().get(i);
                assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
                try {
                    input.getScriptSig().correctlySpends(transaction, i, scriptPubKeys.get(input.getOutpoint()),
                            verifyFlags);
                } catch (VerificationException e) {
                    valid = false;
                }
            }

            if (valid)
                fail();
        }
    }

    @Test
    public void getToAddress() throws Exception {
        // pay to pubkey
        ECKey toKey = new ECKey();
        Address toAddress = toKey.toAddress(params);
        assertEquals(toAddress, ScriptBuilder.createOutputScript(toKey).getToAddress(params, true));
        // pay to pubkey hash
        assertEquals(toAddress, ScriptBuilder.createOutputScript(toAddress).getToAddress(params, true));
        // pay to script hash
        Script p2shScript = ScriptBuilder.createP2SHOutputScript(new byte[20]);
        Address scriptAddress = Address.fromP2SHScript(params, p2shScript);
        assertEquals(scriptAddress, p2shScript.getToAddress(params, true));
    }

    @Test(expected = ScriptException.class)
    public void getToAddressNoPubKey() throws Exception {
        ScriptBuilder.createOutputScript(new ECKey()).getToAddress(params, false);
    }
}
