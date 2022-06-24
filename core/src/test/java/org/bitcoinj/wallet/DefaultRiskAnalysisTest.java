/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.wallet;

import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.testing.FakeTxBuilder;
import org.bitcoinj.wallet.DefaultRiskAnalysis.RuleViolation;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.base.Coin.COIN;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA1;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

public class DefaultRiskAnalysisTest {
    // Uses mainnet because isStandard checks are disabled on testnet.
    private static final NetworkParameters MAINNET = MainNetParams.get();
    private Wallet wallet;
    private final int TIMESTAMP = 1384190189;
    private static final ECKey key1 = new ECKey();
    private final List<Transaction> NO_DEPS = Collections.emptyList();

    @Before
    public void setup() {
        wallet = Wallet.createDeterministic(MAINNET, ScriptType.P2PKH);
        wallet.setLastBlockSeenHeight(1000);
        wallet.setLastBlockSeenTimeSecs(TIMESTAMP);
    }

    @Test(expected = IllegalStateException.class)
    public void analysisCantBeUsedTwice() {
        Transaction tx = new Transaction(MAINNET);
        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.OK, analysis.analyze());
        assertNull(analysis.getNonFinal());
        // Verify we can't re-use a used up risk analysis.
        analysis.analyze();
    }

    @Test
    public void nonFinal() {
        // Verify that just having a lock time in the future is not enough to be considered risky (it's still final).
        Transaction tx = new Transaction(MAINNET);
        TransactionInput input = tx.addInput(MAINNET.getGenesisBlock().getTransactions().get(0).getOutput(0));
        tx.addOutput(COIN, key1);
        tx.setLockTime(TIMESTAMP + 86400);
        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.OK, analysis.analyze());
        assertNull(analysis.getNonFinal());

        // Set a sequence number on the input to make it genuinely non-final. Verify it's risky.
        input.setSequenceNumber(TransactionInput.NO_SEQUENCE - 1);
        analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.NON_FINAL, analysis.analyze());
        assertEquals(tx, analysis.getNonFinal());

        // If the lock time is the current block, it's about to become final and we consider it non-risky.
        tx.setLockTime(1000);
        analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.OK, analysis.analyze());
    }

    @Test
    public void selfCreatedAreNotRisky() {
        Transaction tx = new Transaction(MAINNET);
        tx.addInput(MAINNET.getGenesisBlock().getTransactions().get(0).getOutput(0)).setSequenceNumber(1);
        tx.addOutput(COIN, key1);
        tx.setLockTime(TIMESTAMP + 86400);

        {
            // Is risky ...
            DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
            assertEquals(RiskAnalysis.Result.NON_FINAL, analysis.analyze());
        }
        tx.getConfidence().setSource(TransactionConfidence.Source.SELF);
        {
            // Is no longer risky.
            DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
            assertEquals(RiskAnalysis.Result.OK, analysis.analyze());
        }
    }

    @Test
    public void nonFinalDependency() {
        // Final tx has a dependency that is non-final.
        Transaction tx1 = new Transaction(MAINNET);
        tx1.addInput(MAINNET.getGenesisBlock().getTransactions().get(0).getOutput(0)).setSequenceNumber(1);
        TransactionOutput output = tx1.addOutput(COIN, key1);
        tx1.setLockTime(TIMESTAMP + 86400);
        Transaction tx2 = new Transaction(MAINNET);
        tx2.addInput(output);
        tx2.addOutput(COIN, new ECKey());

        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx2, Collections.singletonList(tx1));
        assertEquals(RiskAnalysis.Result.NON_FINAL, analysis.analyze());
        assertEquals(tx1, analysis.getNonFinal());
    }

    @Test
    public void nonStandardDust() {
        Transaction standardTx = new Transaction(MAINNET);
        standardTx.addInput(MAINNET.getGenesisBlock().getTransactions().get(0).getOutput(0));
        standardTx.addOutput(COIN, key1);
        assertEquals(RiskAnalysis.Result.OK, DefaultRiskAnalysis.FACTORY.create(wallet, standardTx, NO_DEPS).analyze());

        Transaction dustTx = new Transaction(MAINNET);
        dustTx.addInput(MAINNET.getGenesisBlock().getTransactions().get(0).getOutput(0));
        dustTx.addOutput(Coin.SATOSHI, key1); // 1 Satoshi
        assertEquals(RiskAnalysis.Result.NON_STANDARD, DefaultRiskAnalysis.FACTORY.create(wallet, dustTx, NO_DEPS).analyze());

        Transaction edgeCaseTx = new Transaction(MAINNET);
        edgeCaseTx.addInput(MAINNET.getGenesisBlock().getTransactions().get(0).getOutput(0));
        Coin dustThreshold = new TransactionOutput(MAINNET, null, Coin.COIN, key1).getMinNonDustValue();
        edgeCaseTx.addOutput(dustThreshold, key1);
        assertEquals(RiskAnalysis.Result.OK, DefaultRiskAnalysis.FACTORY.create(wallet, edgeCaseTx, NO_DEPS).analyze());
    }

    @Test
    public void nonShortestPossiblePushData() {
        ScriptChunk nonStandardChunk = new ScriptChunk(OP_PUSHDATA1, new byte[75]);
        byte[] nonStandardScript = new ScriptBuilder().addChunk(nonStandardChunk).build().getProgram();
        // Test non-standard script as an input.
        Transaction tx = new Transaction(MAINNET);
        assertEquals(DefaultRiskAnalysis.RuleViolation.NONE, DefaultRiskAnalysis.isStandard(tx));
        tx.addInput(new TransactionInput(MAINNET, null, nonStandardScript));
        assertEquals(DefaultRiskAnalysis.RuleViolation.SHORTEST_POSSIBLE_PUSHDATA, DefaultRiskAnalysis.isStandard(tx));
        // Test non-standard script as an output.
        tx.clearInputs();
        assertEquals(DefaultRiskAnalysis.RuleViolation.NONE, DefaultRiskAnalysis.isStandard(tx));
        tx.addOutput(new TransactionOutput(MAINNET, null, COIN, nonStandardScript));
        assertEquals(DefaultRiskAnalysis.RuleViolation.SHORTEST_POSSIBLE_PUSHDATA, DefaultRiskAnalysis.isStandard(tx));
    }

    @Test
    public void canonicalSignature() {
        TransactionSignature sig = TransactionSignature.dummy();
        Script scriptOk = ScriptBuilder.createInputScript(sig);
        assertEquals(RuleViolation.NONE,
                DefaultRiskAnalysis.isInputStandard(new TransactionInput(MAINNET, null, scriptOk.getProgram())));

        byte[] sigBytes = sig.encodeToBitcoin();
        // Appending a zero byte makes the signature uncanonical without violating DER encoding.
        Script scriptUncanonicalEncoding = new ScriptBuilder().data(Arrays.copyOf(sigBytes, sigBytes.length + 1))
                .build();
        assertEquals(RuleViolation.SIGNATURE_CANONICAL_ENCODING,
                DefaultRiskAnalysis.isInputStandard(new TransactionInput(MAINNET, null, scriptUncanonicalEncoding
                        .getProgram())));
    }

    @Test
    public void canonicalSignatureLowS() throws Exception {
        // First, a synthetic test.
        TransactionSignature sig = TransactionSignature.dummy();
        Script scriptHighS = ScriptBuilder
                .createInputScript(new TransactionSignature(sig.r, ECKey.CURVE.getN().subtract(sig.s)));
        assertEquals(RuleViolation.SIGNATURE_CANONICAL_ENCODING,
                DefaultRiskAnalysis.isInputStandard(new TransactionInput(MAINNET, null, scriptHighS.getProgram())));

        // This is a real transaction. Its signatures S component is "low".
        Transaction tx1 = new Transaction(MAINNET, ByteUtils.HEX.decode(
                "010000000200a2be4376b7f47250ad9ad3a83b6aa5eb6a6d139a1f50771704d77aeb8ce76c010000006a4730440220055723d363cd2d4fe4e887270ebdf5c4b99eaf233a5c09f9404f888ec8b839350220763c3794d310b384ce86decfb05787e5bfa5d31983db612a2dde5ffec7f396ae012102ef47e27e0c4bdd6dc83915f185d972d5eb8515c34d17bad584a9312e59f4e0bcffffffff52239451d37757eeacb86d32864ec1ee6b6e131d1e3fee6f1cff512703b71014030000006b483045022100ea266ac4f893d98a623a6fc0e6a961cd5a3f32696721e87e7570a68851917e75022056d75c3b767419f6f6cb8189a0ad78d45971523908dc4892f7594b75fd43a8d00121038bb455ca101ebbb0ecf7f5c01fa1dcb7d14fbf6b7d7ea52ee56f0148e72a736cffffffff0630b15a00000000001976a9146ae477b690cf85f21c2c01e2c8639a5c18dc884e88ac4f260d00000000001976a91498d08c02ab92a671590adb726dddb719695ee12e88ac65753b00000000001976a9140b2eb4ba6d364c82092f25775f56bc10cd92c8f188ac65753b00000000001976a914d1cb414e22081c6ba3a935635c0f1d837d3c5d9188ac65753b00000000001976a914df9d137a0d279471a2796291874c29759071340b88ac3d753b00000000001976a91459f5aa4815e3aa8e1720e8b82f4ac8e6e904e47d88ac00000000"));
        assertEquals("2a1c8569b2b01ebac647fb94444d1118d4d00e327456a3c518e40d47d72cd5fe", tx1.getTxId().toString());

        assertEquals(RuleViolation.NONE, DefaultRiskAnalysis.isStandard(tx1));

        // This tx is the same as the above, except for a "high" S component on the signature of input 1.
        // It was part of the Oct 2015 malleability attack.
        Transaction tx2 = new Transaction(MAINNET, ByteUtils.HEX.decode(
                "010000000200a2be4376b7f47250ad9ad3a83b6aa5eb6a6d139a1f50771704d77aeb8ce76c010000006a4730440220055723d363cd2d4fe4e887270ebdf5c4b99eaf233a5c09f9404f888ec8b839350220763c3794d310b384ce86decfb05787e5bfa5d31983db612a2dde5ffec7f396ae012102ef47e27e0c4bdd6dc83915f185d972d5eb8515c34d17bad584a9312e59f4e0bcffffffff52239451d37757eeacb86d32864ec1ee6b6e131d1e3fee6f1cff512703b71014030000006c493046022100ea266ac4f893d98a623a6fc0e6a961cd5a3f32696721e87e7570a68851917e75022100a928a3c4898be60909347e765f52872a613d8aada66c57a8c8791316d2f298710121038bb455ca101ebbb0ecf7f5c01fa1dcb7d14fbf6b7d7ea52ee56f0148e72a736cffffffff0630b15a00000000001976a9146ae477b690cf85f21c2c01e2c8639a5c18dc884e88ac4f260d00000000001976a91498d08c02ab92a671590adb726dddb719695ee12e88ac65753b00000000001976a9140b2eb4ba6d364c82092f25775f56bc10cd92c8f188ac65753b00000000001976a914d1cb414e22081c6ba3a935635c0f1d837d3c5d9188ac65753b00000000001976a914df9d137a0d279471a2796291874c29759071340b88ac3d753b00000000001976a91459f5aa4815e3aa8e1720e8b82f4ac8e6e904e47d88ac00000000"));
        assertEquals("dbe4147cf89b89fd9fa6c8ce6a3e2adecb234db094ec88301ae09073ca17d61d", tx2.getTxId().toString());
        assertFalse(ECKey.ECDSASignature
                .decodeFromDER(new Script(tx2.getInputs().get(1).getScriptBytes()).getChunks().get(0).data)
                .isCanonical());

        assertEquals(RuleViolation.SIGNATURE_CANONICAL_ENCODING, DefaultRiskAnalysis.isStandard(tx2));
    }

    @Test
    public void standardOutputs() {
        Transaction tx = new Transaction(MAINNET);
        tx.addInput(MAINNET.getGenesisBlock().getTransactions().get(0).getOutput(0));
        // A pay to address output
        tx.addOutput(Coin.CENT, ScriptBuilder.createP2PKHOutputScript(key1));
        // A P2PK output
        tx.addOutput(Coin.CENT, ScriptBuilder.createP2PKOutputScript(key1));
        tx.addOutput(Coin.CENT, ScriptBuilder.createP2PKOutputScript(key1));
        // 1-of-2 multisig output.
        List<ECKey> keys = Arrays.asList(key1, new ECKey());
        tx.addOutput(Coin.CENT, ScriptBuilder.createMultiSigOutputScript(1, keys));
        // 2-of-2 multisig output.
        tx.addOutput(Coin.CENT, ScriptBuilder.createMultiSigOutputScript(2, keys));
        // P2SH
        tx.addOutput(Coin.CENT, ScriptBuilder.createP2SHOutputScript(1, keys));
        // OP_RETURN
        tx.addOutput(Coin.CENT, ScriptBuilder.createOpReturnScript("hi there".getBytes()));
        assertEquals(RiskAnalysis.Result.OK, DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS).analyze());
    }

    @Test
    public void optInFullRBF() {
        Transaction tx = FakeTxBuilder.createFakeTx(MAINNET);
        tx.getInput(0).setSequenceNumber(TransactionInput.NO_SEQUENCE - 2);
        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.NON_FINAL, analysis.analyze());
        assertEquals(tx, analysis.getNonFinal());
    }

    @Test
    public void relativeLockTime() {
        Transaction tx = FakeTxBuilder.createFakeTx(MAINNET);
        tx.setVersion(2);
        checkState(!tx.hasRelativeLockTime());

        tx.getInput(0).setSequenceNumber(TransactionInput.NO_SEQUENCE);
        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.OK, analysis.analyze());

        tx.getInput(0).setSequenceNumber(0);
        analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.NON_FINAL, analysis.analyze());
        assertEquals(tx, analysis.getNonFinal());
    }

    @Test
    public void transactionVersions() {
        Transaction tx = FakeTxBuilder.createFakeTx(MAINNET);
        tx.setVersion(1);
        DefaultRiskAnalysis analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.OK, analysis.analyze());

        tx.setVersion(2);
        analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.OK, analysis.analyze());

        tx.setVersion(3);
        analysis = DefaultRiskAnalysis.FACTORY.create(wallet, tx, NO_DEPS);
        assertEquals(RiskAnalysis.Result.NON_STANDARD, analysis.analyze());
        assertEquals(tx, analysis.getNonStandard());
    }
}
