/*
 * Copyright 2015 Ross Nicoll.
 * Copyright 2019 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.examples;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.SignatureDecodeException;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptExecution;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bitcoinj.signers.TransactionSigner.ProposedTransaction;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Objects;

import static org.bitcoinj.script.ScriptOpCodes.getOpCodeName;

/**
 * Test case generator for transactions with low-S and high-S signatures, to
 * test the LOW_S script validation flag.
 *
 * @author Ross Nicoll
 */
public class GenerateLowSTests {
    public static final BigInteger HIGH_S_DIFFERENCE = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    public static void main(final String[] argv)
            throws NoSuchAlgorithmException, IOException, VerificationException, SignatureDecodeException {
        final Network network = BitcoinNetwork.MAINNET;
        final LocalTransactionSigner signer = new LocalTransactionSigner();
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        final ECKey key = ECKey.random(secureRandom);
        final KeyBag bag = new KeyBag() {
            @Override
            public ECKey findKeyFromPubKeyHash(byte[] pubkeyHash, ScriptType scriptType) {
                return key;
            }

            @Override
            public ECKey findKeyFromPubKey(byte[] pubKey) {
                return key;
            }

            @Override
            public RedeemData findRedeemDataFromScriptHash(byte[] scriptHash) {
                return null;
            }

        };

        // Generate a fictional output transaction we take values from, and
        // an input transaction for the test case

        final Transaction outputTransaction = new Transaction();
        final Transaction inputTransaction = new Transaction();
        final TransactionOutput output = new TransactionOutput(inputTransaction, Coin.ZERO, key.toAddress(ScriptType.P2PKH, network));

        inputTransaction.addOutput(output);
        outputTransaction.addInput(output);
        outputTransaction.addOutput(Coin.ZERO, ECKey.random(secureRandom).toAddress(ScriptType.P2PKH, network));

        addOutputs(outputTransaction, bag);

        // Sign the transaction
        final ProposedTransaction proposedTransaction = new ProposedTransaction(outputTransaction);
        signer.signInputs(proposedTransaction, bag);
        TransactionInput input = proposedTransaction.partialTx.getInput(0);

        input.verify(output);
        ScriptExecution.correctlySpends(input.getScriptSig(), outputTransaction, 0, null, null, output.getScriptPubKey(),
            EnumSet.of(ScriptExecution.VerifyFlag.DERSIG, ScriptExecution.VerifyFlag.P2SH));

        final Script scriptSig = input.getScriptSig();
        final TransactionSignature signature = TransactionSignature.decodeFromBitcoin(scriptSig.chunks().get(0).pushData(), true, false);

        // First output a conventional low-S transaction with the LOW_S flag, for the tx_valid.json set
        System.out.println("[\"A transaction with a low-S signature.\"],");
        System.out.println("[[[\""
            + inputTransaction.getTxId() + "\", "
            + output.getIndex() + ", \""
            + scriptToString(output.getScriptPubKey()) + "\"]],\n"
            + "\"" + ByteUtils.formatHex(proposedTransaction.partialTx.serialize()) + "\", \""
            + ScriptExecution.VerifyFlag.P2SH.name() + "," + ScriptExecution.VerifyFlag.LOW_S.name() + "\"],");

        final BigInteger highS = HIGH_S_DIFFERENCE.subtract(signature.s);
        final TransactionSignature highSig = new TransactionSignature(signature.r, highS);
        input = input.withScriptSig(new ScriptBuilder().data(highSig.encodeToBitcoin()).data(scriptSig.chunks().get(1).pushData()).build());
        ScriptExecution.correctlySpends(input.getScriptSig(), outputTransaction, 0, null, null, output.getScriptPubKey(),
            EnumSet.of(ScriptExecution.VerifyFlag.P2SH));

        // A high-S transaction without the LOW_S flag, for the tx_valid.json set
        System.out.println("[\"A transaction with a high-S signature.\"],");
        System.out.println("[[[\""
            + inputTransaction.getTxId() + "\", "
            + output.getIndex() + ", \""
            + scriptToString(output.getScriptPubKey()) + "\"]],\n"
            + "\"" + ByteUtils.formatHex(proposedTransaction.partialTx.serialize()) + "\", \""
            + ScriptExecution.VerifyFlag.P2SH.name() + "\"],");

        // Lastly a conventional high-S transaction with the LOW_S flag, for the tx_invalid.json set
        System.out.println("[\"A transaction with a high-S signature.\"],");
        System.out.println("[[[\""
            + inputTransaction.getTxId() + "\", "
            + output.getIndex() + ", \""
            + scriptToString(output.getScriptPubKey()) + "\"]],\n"
            + "\"" + ByteUtils.formatHex(proposedTransaction.partialTx.serialize()) + "\", \""
            + ScriptExecution.VerifyFlag.P2SH.name() + "," + ScriptExecution.VerifyFlag.LOW_S.name() + "\"],");
    }

    private static void addOutputs(final Transaction outputTransaction, final KeyBag bag) throws ScriptException {
        int numInputs = outputTransaction.getInputs().size();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = outputTransaction.getInput(i);
            Script scriptPubKey = txIn.getConnectedOutput().getScriptPubKey();
            RedeemData redeemData = txIn.getConnectedRedeemData(bag);
            Objects.requireNonNull(redeemData, () ->
                    "Transaction exists in wallet that we cannot redeem: " + txIn.getOutpoint().hash());
            outputTransaction.replaceInput(i, txIn.withScriptSig(scriptPubKey.createEmptyInputScript(redeemData.keys.get(0), redeemData.redeemScript)));
        }
    }

    /**
     * Convert a script to a string format that suits the style expected in
     * tx_valid.json and tx_invalid.json.
     */
    private static String scriptToString(Script scriptPubKey) {
        final StringBuilder buf = new StringBuilder();
        for (ScriptChunk chunk: scriptPubKey.chunks()) {
            if (buf.length() > 0) {
                buf.append(" ");
            }
            if (chunk.isOpCode()) {
                buf.append(chunk.opCodeName());
            } else if (chunk.pushData() != null) {
                // Data chunk
                buf.append("0x")
                    .append(chunk.opCodeHex()).append(" 0x")
                    .append(ByteUtils.formatHex(chunk.pushData()));
            } else {
                buf.append(chunk.toString());
            }
        }
        return buf.toString();
    }
}
