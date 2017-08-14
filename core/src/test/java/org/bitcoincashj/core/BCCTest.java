/*
 * Copyright 2017 Wang Jinbo
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

import org.bitcoincashj.crypto.TransactionSignature;
import org.bitcoincashj.params.RegTestParams;
import org.bitcoincashj.script.Script;
import org.bitcoincashj.script.ScriptBuilder;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A draft of test cases for Bitcoin Cash signature
 */
public class BCCTest {

    private static final NetworkParameters PARAMS = RegTestParams.get();

    @Test
    public void testP2SHMultiSign() {
        ECKey key1 = DumpedPrivateKey.fromBase58(PARAMS, "cUfapEEhg2y9a7U135VVEe5fz52Zhf1Sytu4voet527PcUvTDw62").getKey();
        ECKey key2 = DumpedPrivateKey.fromBase58(PARAMS, "cReifGpzVzS1LynpwMpoMxeF537cs3MhSxznWysiRtAemJgkgQnF").getKey();

        Address destAddress = Address.fromBase58(PARAMS, "mhwQAhYxou8Z1nfVNeJQmopPvfaoCTYa7N");

        List<ECKey> keys = new ArrayList<ECKey>();
        keys.add(key1);
        keys.add(key2);

        Collections.sort(keys, ECKey.PUBKEY_COMPARATOR);

        Script scriptPubKey = ScriptBuilder.createP2SHOutputScript(2, keys);
        Address p2shAddress = Address.fromP2SHScript(PARAMS, scriptPubKey);

        System.out.println(p2shAddress.toBase58());

        Transaction tx = new Transaction(PARAMS);
        Script redeemScript = ScriptBuilder.createRedeemScript(2, keys);

        tx.addInput(new Sha256Hash("a7686b3919526a6e733ccd1a2413f517ae44bb01a31cb4d2caaa173dc69b6b85"), 1, scriptPubKey);
        tx.addOutput(Coin.valueOf(0, 99), destAddress);


        List<TransactionSignature> signatures = new ArrayList<TransactionSignature>();
        for (ECKey key : keys) {
            Sha256Hash hash = tx.hashForSignature(0, redeemScript, Transaction.SigHash.ALL, false, 100000000L);
            ECKey.ECDSASignature sig = key.sign(hash);
            TransactionSignature signature = new TransactionSignature(sig, Transaction.SigHash.ALL, false, true);
            signatures.add(signature);
        }

        Script scriptSig = ScriptBuilder.createP2SHMultiSigInputScript(signatures, redeemScript);
        tx.getInput(0).setScriptSig(scriptSig);

        System.out.println(Utils.HEX.encode(tx.bitcoinSerialize()));

        // TODO: This will fail. org.bitcoincashj.script.Script.executeMultiSig() should be updated
        // tx.getInput(0).verify(output);
    }

    @Test
    public void testP2PKHSign() {
        String privateKey = "cVnNvNhLQzxAT7MzUfv8gMmXAJWnDKtNQe2cnTuipVV6khePqkhQ";
        DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(PARAMS, privateKey);
        ECKey ecKey = dumpedPrivateKey.getKey();

        Address address = ecKey.toAddress(PARAMS);
        System.out.println(address);

        Script scriptPubKey = ScriptBuilder.createOutputScript(address);

        Address destAddress = Address.fromBase58(PARAMS, "n2KoWcSEaw3hjoqU7fZaRo6XMYXuKCTf1Q");

        Transaction tx0 = new Transaction(PARAMS);

        Transaction tx = new Transaction(PARAMS);
        tx.setVersion(2);
        tx.addInput(new Sha256Hash("c3d8c742bccfc40161bcd4288727d5b77ce653aa483c89ad9090f95c844c89ed"), 0, scriptPubKey);
        tx.addOutput(Coin.valueOf(0, 99), destAddress);

        Sha256Hash hash = tx.hashForSignature(0, scriptPubKey, Transaction.SigHash.ALL, false, 100000000L);
        ECKey.ECDSASignature sig = ecKey.sign(hash);

        TransactionSignature signature = new TransactionSignature(sig, Transaction.SigHash.ALL, false, true);
        Script scriptSig = ScriptBuilder.createInputScript(signature, ecKey);
        tx.getInput(0).setScriptSig(scriptSig);

        System.out.println(Utils.HEX.encode(tx.bitcoinSerialize()));

        // TODO: This will fail. org.bitcoincashj.script.Script.executeCheckSig() should be updated
//         tx.getInput(0).verify(output);
    }
}
