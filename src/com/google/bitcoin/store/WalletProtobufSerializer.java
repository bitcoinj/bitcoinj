/**
 * Copyright 2012 Google Inc.
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

package com.google.bitcoin.store;

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.StoredBlock;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.core.WalletTransaction;
import com.google.protobuf.ByteString;

import org.bitcoinj.wallet.Protos;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Serialize and de-serialize a wallet to a protobuf stream.
 * 
 * @author Miron Cuperman
 */
public class WalletProtobufSerializer {
    void writeWallet(Wallet wallet, OutputStream output) throws IOException {
        Protos.Wallet.Builder walletBuilder = Protos.Wallet.newBuilder();
        walletBuilder
            .setNetworkIdentifier(wallet.getNetworkParameters().getId())
            .setLastSeenBlockHash(null)  // TODO
            ;
        for (WalletTransaction wtx : wallet.getWalletTransactions()) {
            Protos.Wallet.Transaction txProto = makeTxProto(wtx);
            walletBuilder.addTransaction(txProto);
        }
        
        for (ECKey key : wallet.getKeys()) {
            final String base58PrivateKey =
                    key.getPrivateKeyEncoded(wallet.getNetworkParameters()).toString();
            walletBuilder.addKey(
                    Protos.Wallet.Key.newBuilder()
                        // .setCreationTimestamp() TODO
                        // .setLabel() TODO
                        .setPrivateKey(base58PrivateKey));
        }
        
        walletBuilder.build().writeTo(output);
    }

    private Protos.Wallet.Transaction makeTxProto(WalletTransaction wtx) {
        Transaction tx = wtx.getTransaction();
        Protos.Wallet.Transaction.Builder txBuilder = Protos.Wallet.Transaction.newBuilder();
        
        txBuilder
            .setUpdatedAt(tx.getUpdateTime().getTime())
            .setPool(Protos.Wallet.Transaction.Pool.valueOf(wtx.getPool().getValue()));
        
        // Handle inputs
        for (TransactionInput input : tx.getInputs()) {
            txBuilder.addTransactionInput(
                    Protos.Wallet.Transaction.TransactionInput.newBuilder()
                    .setScriptBytes(ByteString.copyFrom(input.getScriptBytes()))
                    .setTransactionOutPointHash(ByteString.copyFrom(
                            input.getOutpoint().getHash().getBytes()))
                    .setTransactionOutPointIndex((int)input.getOutpoint().getIndex()) // FIXME
                    );
        }
        
        // Handle outputs
        for (TransactionOutput output : tx.getOutputs()) {
            final TransactionInput spentBy = output.getSpentBy();
            txBuilder.addTransactionOutput(
                    Protos.Wallet.Transaction.TransactionOutput.newBuilder()
                    .setScriptBytes(ByteString.copyFrom(output.getScriptBytes()))
                    .setSpentByTransactionHash(ByteString.copyFrom(
                            spentBy.getHash().getBytes()))
                    .setSpentByTransactionIndex((int)spentBy.getOutpoint().getIndex()) // FIXME
                    .setValue(output.getValue().longValue())
                    );
        }
        
        // Handle which blocks tx was seen in
        for (StoredBlock block : tx.getAppearsIn()) {
            txBuilder.addBlockHash(ByteString.copyFrom(block.getHeader().getHash().getBytes()));
        }
        
        return txBuilder.build();
    }
}
