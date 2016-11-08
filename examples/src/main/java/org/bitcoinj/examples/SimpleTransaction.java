/*
 * Copyright 2016 Jean-Pierre Rupp
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

package org.bitcoinj.examples;

import org.bitcoinj.core.*;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.spongycastle.util.encoders.Hex;

/**
 * This example shows how to build a simple transaction
 */
public class SimpleTransaction {
    public static void main(String[] args) throws Exception {
        NetworkParameters params = TestNet3Params.get();

        final String wif = "cVXrjQt281reTcZ6eieWnbDgZsFHKApoKnU4P7j82jEBrecJB75G";
        final ECKey key = DumpedPrivateKey.fromBase58(params, wif).getKey();
        final Address address = key.toAddress(params); // mhrwYyunFdkP7RuBZLMND7fhu8aH1QETfE
        final Sha256Hash txid = Sha256Hash.wrap("488d7c1595a8aee30ccf7bd82b2cc5b7fb94c5f256b55baa519675b72cbf2fdd");
        final Long index = 1L;
        final Coin amount = Coin.MILLICOIN;
        final TransactionOutPoint outPoint = new TransactionOutPoint(params, index, txid);
        final Script pkScript = ScriptBuilder.createOutputScript(address);

        // Build transaction
        final Address spendto = Address.fromBase58(params, "mpeoG6pjLH6yDodyjqTaLZuEz7LEjEbYa5");
        final Transaction transaction = new Transaction(params);
        final Coin fee = Coin.SATOSHI.times(10000);
        transaction.addOutput(amount.minus(fee), spendto);
        transaction.addSignedInput(outPoint, pkScript, key);
        final String id = Hex.toHexString(transaction.getHash().getBytes());
        System.out.println(Hex.toHexString(transaction.bitcoinSerialize()));
    }
}
