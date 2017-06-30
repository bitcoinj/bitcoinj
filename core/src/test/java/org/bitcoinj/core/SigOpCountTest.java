/*
 * Copyright 2017 Jean-Pierre Rupp
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

import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptOpCodes;
import org.junit.Test;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class SigOpCountTest {
    final static private NetworkParameters PARAMS = UnitTestParams.get();

    final static private ECKey key = new ECKey();
    final static private Set<Script.VerifyFlag> flags = EnumSet.of(Script.VerifyFlag.P2SH, Script.VerifyFlag.SEGWIT);

    /**
     * Verify script execution of first pkScript of tx output against first sigScript (and witness) of tx input.
     *
     * @param output transaction with first output that spent by input transaction.
     * @param input transaction whose first input spends first output of output transaction.
     * @param flagSet flags for verification algorithm.
     * @return whether script execution succeeds.
     */
    static boolean verifyWithFlags(
            final Transaction output,
            final Transaction input,
            final Set<Script.VerifyFlag> flagSet)
    {
        try {
            input.getInput(0).verify(output.getOutput(0), flagSet);
        } catch (ScriptException e) {
            return false;
        }
        return true;
    }

    static int countSigOps(
            final Transaction tx,
            @Nullable final TransactionWitness witness,
            @Nullable List<Script> pkScripts,
            final Set<Script.VerifyFlag> flagSet)
    {
        int sigOps = 0;
        for (int i = 0; i < tx.getInputs().size(); i++) {
            final TransactionInput input = tx.getInput(i);
            if (pkScripts == null)
                sigOps += input.countSigOps();
            else
                sigOps += input.countSigOps(flagSet, pkScripts.get(i), witness);
        }
        for (TransactionOutput output : tx.getOutputs())
            sigOps += output.countSigOps();
        return sigOps;
    }

    /**
     * Builds a creationTx from pkScript and a spendingTx from sigScript
     * and witness such that spendingTx spends output zero of creationTx.
     *
     * Output of creationTx is connected to input from spendingTx.
     *
     * @param pkScript script for single 1-satoshi output on creationTx.
     * @param sigScript script spending pkScript, will be only input on spendingTx.
     * @param witness witness for sigScript input. Excluded if null.
     * @return list of creationTx and spendingTx.
     */
    static List<Transaction> buildTxs(
            final Script pkScript,
            final Script sigScript,
            @Nullable final TransactionWitness witness)
    {
        final Transaction creationTx = new Transaction(PARAMS);
        final TransactionInput creationInput =
                new TransactionInput(
                        PARAMS,
                        null,
                        new byte[0]);
        creationTx.addInput(creationInput);
        final TransactionOutput creationOutput =
                new TransactionOutput(
                        PARAMS,
                        null,
                        Coin.SATOSHI,
                        pkScript.getProgram());
        creationTx.addOutput(creationOutput);

        final Transaction spendingTx = new Transaction(PARAMS);
        final TransactionInput spendingInput =
                new TransactionInput(
                        PARAMS,
                        null,
                        sigScript.getProgram(),
                        creationOutput.getOutPointFor());
        spendingTx.addInput(spendingInput);
        spendingInput.connect(creationOutput);
        final TransactionOutput spendingOutput =
                new TransactionOutput(
                        PARAMS,
                        null,
                        Coin.SATOSHI,
                        new byte[0]);
        spendingTx.addOutput(spendingOutput);
        if (witness != null)
            spendingTx.setWitness(0, witness);

        final ArrayList<Transaction> txs = new ArrayList<>();
        txs.add(creationTx);
        txs.add(spendingTx);

        return txs;
    }

    @Test
    public void multisig() {
        final ArrayList<ECKey> keys = new ArrayList<>();
        keys.add(key);
        keys.add(key);
        final Script pkScript = ScriptBuilder.createMultiSigOutputScript(1, keys);
        final Script sigScript = new ScriptBuilder()
                .smallNum(0)
                .smallNum(0)
                .build();
        final List<Transaction> txs = buildTxs(pkScript, sigScript, null);
        final Transaction creationTx = txs.get(0);
        final Transaction spendingTx = txs.get(1);
        assertEquals(
                0,
                countSigOps(spendingTx, null, singletonList(pkScript), flags));
        assertEquals(
                Script.MAX_PUBKEYS_PER_MULTISIG * Transaction.WITNESS_SCALE_FACTOR,
                countSigOps(creationTx, null, null, flags));
        assertFalse(
                verifyWithFlags(creationTx, spendingTx, flags));
    }

    @Test
    public void multisigP2SH() {
        final ArrayList<ECKey> keys = new ArrayList<>();
        keys.add(key);
        keys.add(key);
        final Script redeemScript = ScriptBuilder.createRedeemScript(1, keys);
        final Script pkScript = ScriptBuilder.createP2SHOutputScript(redeemScript);
        final Script sigScript = new ScriptBuilder()
                .smallNum(0)
                .smallNum(0)
                .data(redeemScript.getProgram())
                .build();
        final List<Transaction> txs = buildTxs(pkScript, sigScript, null);
        final Transaction creationTx = txs.get(0);
        final Transaction spendingTx = txs.get(1);
        assertEquals(
                2 * Transaction.WITNESS_SCALE_FACTOR,
                countSigOps(spendingTx, null, singletonList(pkScript), flags));
        assertFalse(
                verifyWithFlags(creationTx, spendingTx, flags));
    }

    @Test
    public void p2wpkh() {
        final Script pkScript = ScriptBuilder.createP2WPKHOutputScript(key);
        final Script sigScript = new ScriptBuilder().build();
        final TransactionWitness witness = new TransactionWitness(2);
        witness.setPush(0, new byte[0]);
        witness.setPush(1, new byte[0]);
        final List<Transaction> txs = buildTxs(pkScript, sigScript, witness);
        final Transaction creationTx = txs.get(0);
        final Transaction spendingTx = txs.get(1);
        assertEquals(
                1,
                countSigOps(spendingTx, witness, singletonList(pkScript), flags));
        assertEquals(
                0,
                countSigOps(spendingTx, witness, singletonList(pkScript), EnumSet.of(Script.VerifyFlag.P2SH)));
        assertFalse(verifyWithFlags(creationTx, spendingTx, flags));
    }

    @Test
    public void unknownWitnessVersion() {
        final Script pkScript = new ScriptBuilder()
                .number(0x51)
                .data(key.getPubKeyHash())
                .build();
        final Script sigScript = new ScriptBuilder().build();
        final TransactionWitness witness = new TransactionWitness(2);
        witness.setPush(0, new byte[0]);
        witness.setPush(1, new byte[0]);
        final List<Transaction> txs = buildTxs(pkScript, sigScript, witness);
        final Transaction creationTx = txs.get(0);
        final Transaction spendingTx = txs.get(1);
        assertEquals(
                0,
                countSigOps(spendingTx, witness, singletonList(pkScript), flags));
    }

    @Test
    public void p2wpkhP2SH() {
        final Script redeemScript = ScriptBuilder.createP2WPKHOutputScript(key);
        final Script pkScript = ScriptBuilder.createP2SHOutputScript(redeemScript);
        final Script sigScript = new ScriptBuilder()
                .data(redeemScript.getProgram())
                .build();
        final TransactionWitness witness = new TransactionWitness(2);
        witness.setPush(0, new byte[0]);
        witness.setPush(1, new byte[1]);
        final List<Transaction> txs = buildTxs(pkScript, sigScript, witness);
        final Transaction creationTx = txs.get(0);
        final Transaction spendingTx = txs.get(1);
        assertEquals(
                1,
                countSigOps(spendingTx, witness, singletonList(pkScript), flags));
        assertFalse(
                verifyWithFlags(creationTx, spendingTx, flags));
    }

    @Test
    public void p2wsh() {
        final ArrayList<ECKey> keys = new ArrayList<>();
        keys.add(key);
        keys.add(key);
        final Script witnessScript = ScriptBuilder.createMultiSigOutputScript(1, keys);
        final Script pkScript = ScriptBuilder.createP2WSHOutputScript(witnessScript);
        final Script sigScript = new ScriptBuilder().build();
        final TransactionWitness witness = new TransactionWitness(3);
        witness.setPush(0, new byte[0]);
        witness.setPush(1, new byte[0]);
        witness.setPush(2, witnessScript.getProgram());
        final List<Transaction> txs = buildTxs(pkScript, sigScript, witness);
        final Transaction creationTx = txs.get(0);
        final Transaction spendingTx = txs.get(1);
        assertEquals(
                2,
                countSigOps(spendingTx, witness, singletonList(pkScript), flags));
        assertEquals(
                0,
                countSigOps(spendingTx, witness, singletonList(pkScript), EnumSet.of(Script.VerifyFlag.P2SH)));
        assertFalse(
                verifyWithFlags(creationTx, spendingTx, flags));
    }

    @Test
    public void p2wshP2SH() {
        final ArrayList<ECKey> keys = new ArrayList<>();
        keys.add(key);
        keys.add(key);
        final Script witnessScript = ScriptBuilder.createMultiSigOutputScript(1, keys);
        final Script redeemScript = ScriptBuilder.createP2WSHOutputScript(witnessScript);
        final Script pkScript = ScriptBuilder.createP2SHOutputScript(redeemScript);
        final Script sigScript = new ScriptBuilder()
                .data(redeemScript.getProgram())
                .build();
        final TransactionWitness witness = new TransactionWitness(3);
        witness.setPush(0, new byte[0]);
        witness.setPush(1, new byte[1]);
        witness.setPush(2, witnessScript.getProgram());
        final List<Transaction> txs = buildTxs(pkScript, sigScript, witness);
        final Transaction creationTx = txs.get(0);
        final Transaction spendingTx = txs.get(1);
        assertEquals(
                2,
                countSigOps(spendingTx, witness, singletonList(pkScript), flags));
        assertFalse(
                verifyWithFlags(creationTx, spendingTx, flags));
    }
}
