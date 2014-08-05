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

package com.google.bitcoin.script;

import com.google.bitcoin.core.*;
import com.google.bitcoin.core.Transaction.SigHash;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.params.TestNet3Params;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.hamcrest.core.IsNot;
import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.*;

import static com.google.bitcoin.core.Utils.HEX;
import static com.google.bitcoin.script.ScriptOpCodes.OP_0;
import static com.google.bitcoin.script.ScriptOpCodes.OP_INVALIDOPCODE;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.*;

public class ScriptTest {
    // From tx 05e04c26c12fe408a3c1b71aa7996403f6acad1045252b1c62e055496f4d2cb1 on the testnet.

    static final String sigProg = "47304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c";

    static final String pubkeyProg = "76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac";


    static final NetworkParameters params = TestNet3Params.get();

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
    public void testCreateEmptyInputScript() throws Exception {
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
    }
    
    private Script parseScriptString(String string) throws Exception {
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
    
    @Test
    public void dataDrivenValidScripts() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("script_valid.json"), Charset.forName("UTF-8")));

        NetworkParameters params = TestNet3Params.get();
        
        // Poor man's JSON parser (because pulling in a lib for this is overkill)
        String script = "";
        while (in.ready()) {
            String line = in.readLine();
            if (line == null || line.equals("")) continue;
            script += line;
            if (line.equals("]") && script.equals("]") && !in.ready())
                break; // ignore last ]
            if (line.trim().endsWith("],") || line.trim().endsWith("]")) {
                String[] scripts = script.split(",");

                scripts[0] = scripts[0].replaceAll("[\"\\[\\]]", "").trim();
                scripts[1] = scripts[1].replaceAll("[\"\\[\\]]", "").trim();
                Script scriptSig = parseScriptString(scripts[0]);
                Script scriptPubKey = parseScriptString(scripts[1]);

                try {
                    scriptSig.correctlySpends(new Transaction(params), 0, scriptPubKey, true);
                } catch (ScriptException e) {
                    System.err.println("scriptSig: " + scripts[0]);
                    System.err.println("scriptPubKey: " + scripts[1]);
                    System.err.flush();
                    throw e;
                }
                script = "";
            }
        }
        in.close();
    }
    
    @Test
    public void dataDrivenInvalidScripts() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("script_invalid.json"), Charset.forName("UTF-8")));

        NetworkParameters params = TestNet3Params.get();
        
        // Poor man's JSON parser (because pulling in a lib for this is overkill)
        String script = "";
        while (in.ready()) {
            String line = in.readLine();
            if (line == null || line.equals("")) continue;
            script += line;
            if (line.equals("]") && script.equals("]") && !in.ready())
                break; // ignore last ]
            if (line.trim().endsWith("],") || line.trim().equals("]")) {
                String[] scripts = script.split(",");
                try {                    
                    scripts[0] = scripts[0].replaceAll("[\"\\[\\]]", "").trim();
                    scripts[1] = scripts[1].replaceAll("[\"\\[\\]]", "").trim();
                    Script scriptSig = parseScriptString(scripts[0]);
                    Script scriptPubKey = parseScriptString(scripts[1]);

                    scriptSig.correctlySpends(new Transaction(params), 0, scriptPubKey, true);
                    System.err.println("scriptSig: " + scripts[0]);
                    System.err.println("scriptPubKey: " + scripts[1]);
                    System.err.flush();
                    fail();
                } catch (VerificationException e) {
                    // Expected.
                }
                script = "";
            }
        }
        in.close();
    }
    
    private static class JSONObject {
        String string;
        List<JSONObject> list;
        boolean booleanValue;
        Integer integer;
        JSONObject(String string) { this.string = string; }
        JSONObject(List<JSONObject> list) { this.list = list; }
        JSONObject(Integer integer) { this.integer = integer; }
        JSONObject(boolean value) { this.booleanValue = value; }
        boolean isList() { return list != null; }
        boolean isString() { return string != null; }
        boolean isInteger() { return integer != null; }
        boolean isBoolean() { return !isList() && !isString() && !isInteger(); }
    }
    
    private boolean appendToList(List<JSONObject> tx, StringBuffer buffer) {
        if (buffer.length() == 0)
            return true;
        switch(buffer.charAt(0)) {
        case '[':
            int closePos = 0;
            boolean inString = false;
            int inArray = 0;
            for (int i = 1; i < buffer.length() && closePos == 0; i++) {
                switch (buffer.charAt(i)) {
                case '"':
                    if (buffer.charAt(i-1) != '\\')
                        inString = !inString;
                    break;
                case ']':
                    if (!inString) {
                        if (inArray == 0)
                            closePos = i;
                        else
                            inArray--;
                    }
                    break;
                case '[':
                    if (!inString)
                        inArray++;
                    break;
                default:
                    break;
                }
            }
            if (inArray != 0 || closePos == 0)
                return false;
            List<JSONObject> subList = new ArrayList<JSONObject>(5);
            StringBuffer subBuff = new StringBuffer(buffer.substring(1, closePos));
            boolean finished = appendToList(subList, subBuff);
            if (finished) {
                buffer.delete(0, closePos + 1);
                tx.add(new JSONObject(subList));
                return appendToList(tx, buffer);
            } else
                return false;
        case '"':
            int finishPos = 0;
            do {
                finishPos = buffer.indexOf("\"", finishPos + 1);
            } while (finishPos == -1 || buffer.charAt(finishPos - 1) == '\\');
            if (finishPos == -1)
                return false;
            tx.add(new JSONObject(buffer.substring(1, finishPos)));
            buffer.delete(0, finishPos + 1);
            return appendToList(tx, buffer);
        case ',':
        case ' ':
            buffer.delete(0, 1);
            return appendToList(tx, buffer);
        default:
            String first = buffer.toString().split(",")[0].trim();
            if (first.equals("true")) {
                tx.add(new JSONObject(true));
                buffer.delete(0, 4);
                return appendToList(tx, buffer);
            } else if (first.equals("false")) {
                tx.add(new JSONObject(false));
                buffer.delete(0, 5);
                return appendToList(tx, buffer);
            } else if (first.matches("^-?[0-9]*$")) {
                tx.add(new JSONObject(Integer.parseInt(first)));
                buffer.delete(0, first.length());
                return appendToList(tx, buffer);
            } else
                fail();
        }
        return false;
    }
    
    @Test
    public void dataDrivenValidTransactions() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("tx_valid.json"), Charset.forName("UTF-8")));

        NetworkParameters params = TestNet3Params.get();
        
        // Poor man's (aka. really, really poor) JSON parser (because pulling in a lib for this is probably not overkill)
        int lineNum = -1;
        List<JSONObject> tx = new ArrayList<JSONObject>(3);
        in.read(); // remove first [
        StringBuffer buffer = new StringBuffer(1000);
        while (in.ready()) {
            lineNum++;
            String line = in.readLine();
            if (line == null || line.equals("")) continue;
            buffer.append(line);
            if (line.equals("]") && buffer.toString().equals("]") && !in.ready())
                break;
            boolean isFinished = appendToList(tx, buffer);
            while (tx.size() > 0 && tx.get(0).isList() && tx.get(0).list.size() == 1 && tx.get(0).list.get(0).isString())
                tx.remove(0); // ignore last ]
            if (isFinished && tx.size() == 1 && tx.get(0).list.size() == 3) {
                Transaction transaction = null;
                try {
                    HashMap<TransactionOutPoint, Script> scriptPubKeys = new HashMap<TransactionOutPoint, Script>();
                    for (JSONObject input : tx.get(0).list.get(0).list) {
                        String hash = input.list.get(0).string;
                        int index = input.list.get(1).integer;
                        String script = input.list.get(2).string;
                        Sha256Hash sha256Hash = new Sha256Hash(HEX.decode(hash));
                        scriptPubKeys.put(new TransactionOutPoint(params, index, sha256Hash), parseScriptString(script));
                    }

                    transaction = new Transaction(params, HEX.decode(tx.get(0).list.get(1).string.toLowerCase()));
                    boolean enforceP2SH = tx.get(0).list.get(2).booleanValue;
                    assertTrue(tx.get(0).list.get(2).isBoolean());

                    transaction.verify();

                    for (int i = 0; i < transaction.getInputs().size(); i++) {
                        TransactionInput input = transaction.getInputs().get(i);
                        if (input.getOutpoint().getIndex() == 0xffffffffL)
                            input.getOutpoint().setIndex(-1);
                        assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
                        input.getScriptSig().correctlySpends(transaction, i, scriptPubKeys.get(input.getOutpoint()), enforceP2SH);
                    }
                    tx.clear();
                } catch (Exception e) {
                    System.err.println("Exception processing line " + lineNum + ": " + line);
                    if (transaction != null)
                        System.err.println(transaction);
                    throw e;
                }
            }
        }
        in.close();
    }

    @Test
    public void dataDrivenInvalidTransactions() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("tx_invalid.json"), Charset.forName("UTF-8")));

        NetworkParameters params = TestNet3Params.get();
        
        // Poor man's (aka. really, really poor) JSON parser (because pulling in a lib for this is probably overkill)
        List<JSONObject> tx = new ArrayList<JSONObject>(1);
        in.read(); // remove first [
        StringBuffer buffer = new StringBuffer(1000);
        while (in.ready()) {
            String line = in.readLine();
            if (line == null || line.equals(""))
                continue;
            buffer.append(line);
            if (line.equals("]") && buffer.toString().equals("]") && !in.ready())
                break; // ignore last ]
            boolean isFinished = appendToList(tx, buffer);
            while (tx.size() > 0 && tx.get(0).isList() && tx.get(0).list.size() == 1 && tx.get(0).list.get(0).isString())
                tx.remove(0);
            if (isFinished && tx.size() == 1 && tx.get(0).list.size() == 3) {
                HashMap<TransactionOutPoint, Script> scriptPubKeys = new HashMap<TransactionOutPoint, Script>();
                for (JSONObject input : tx.get(0).list.get(0).list) {
                    String hash = input.list.get(0).string;
                    int index = input.list.get(1).integer;
                    String script = input.list.get(2).string;
                    Sha256Hash sha256Hash = new Sha256Hash(HEX.decode(hash));
                    scriptPubKeys.put(new TransactionOutPoint(params, index, sha256Hash), parseScriptString(script));
                }

                Transaction transaction = new Transaction(params, HEX.decode(tx.get(0).list.get(1).string));
                boolean enforceP2SH = tx.get(0).list.get(2).booleanValue;
                assertTrue(tx.get(0).list.get(2).isBoolean());
                
                
                boolean valid = true;
                try {
                    transaction.verify();
                } catch (VerificationException e) {
                    valid = false;
                }
                
                // The reference client checks this case in CheckTransaction, but we leave it to
                // later where we will see an attempt to double-spend, so we explicitly check here
                HashSet<TransactionOutPoint> set = new HashSet<TransactionOutPoint>();
                for(TransactionInput input : transaction.getInputs()) {
                    if (set.contains(input.getOutpoint()))
                        valid = false;
                    set.add(input.getOutpoint());
                }
                
                for (int i = 0; i < transaction.getInputs().size() && valid; i++) {
                    TransactionInput input = transaction.getInputs().get(i);
                    assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
                    try {
                        input.getScriptSig().correctlySpends(transaction, i, scriptPubKeys.get(input.getOutpoint()), enforceP2SH);
                    } catch (VerificationException e) {
                        valid = false;
                    }
                }
                
                if (valid)
                    fail();
                
                tx.clear();
            }
        }
        in.close();
    }
}
