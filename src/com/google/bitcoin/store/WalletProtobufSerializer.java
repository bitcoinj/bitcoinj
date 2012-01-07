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

import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.DumpedPrivateKey;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.StoredBlock;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.core.TransactionOutPoint;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.core.WalletTransaction;
import com.google.protobuf.ByteString;

import org.bitcoinj.wallet.Protos;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Serialize and de-serialize a wallet to a protobuf stream.
 * 
 * @author Miron Cuperman
 */
public class WalletProtobufSerializer {
    // Used for de-serialization
    private Map<ByteString, Transaction> txMap;
    
    public WalletProtobufSerializer() {
        txMap = new HashMap<ByteString, Transaction>();
    }
    
    static public void writeWallet(Wallet wallet, OutputStream output) throws IOException {
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
    
    private static Protos.Wallet.Transaction makeTxProto(WalletTransaction wtx) {
        Transaction tx = wtx.getTransaction();
        Protos.Wallet.Transaction.Builder txBuilder = Protos.Wallet.Transaction.newBuilder();
        
        txBuilder
            .setUpdatedAt(tx.getUpdateTime().getTime())
            .setPool(Protos.Wallet.Transaction.Pool.valueOf(wtx.getPool().getValue()))
            .setHash(ByteString.copyFrom(tx.getHash().getBytes()))
            ;
        
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
            Protos.Wallet.Transaction.TransactionOutput.Builder outputBuilder =
                    Protos.Wallet.Transaction.TransactionOutput.newBuilder()
                        .setScriptBytes(ByteString.copyFrom(output.getScriptBytes()))
                        .setValue(output.getValue().longValue());
            final TransactionInput spentBy = output.getSpentBy();
            if (spentBy != null) {
                outputBuilder
                    .setSpentByTransactionHash(ByteString.copyFrom(spentBy.getHash().getBytes()))
                    .setSpentByTransactionIndex((int)spentBy.getOutpoint().getIndex()); // FIXME
            }
            txBuilder.addTransactionOutput(outputBuilder);
        }
        
        // Handle which blocks tx was seen in
        for (StoredBlock block : tx.getAppearsIn()) {
            txBuilder.addBlockHash(ByteString.copyFrom(block.getHeader().getHash().getBytes()));
        }
        
        return txBuilder.build();
    }

    static public Wallet readWallet(InputStream input, NetworkParameters params, BlockStore store)
            throws IOException, AddressFormatException, BlockStoreException {
        WalletProtobufSerializer serializer = new WalletProtobufSerializer();
        Protos.Wallet walletProto = Protos.Wallet.parseFrom(input);
        if (!params.getId().equals(walletProto.getNetworkIdentifier()))
            throw new IllegalArgumentException(
                    "Trying to read a wallet with a different network id " +
                    walletProto.getNetworkIdentifier());
        
        Wallet wallet = new Wallet(params);
        
        // Read all keys
        for (Protos.Wallet.Key keyProto : walletProto.getKeyList()) {
            wallet.addKey(new DumpedPrivateKey(params, keyProto.getPrivateKey()).getKey());
        }
        
        // Read all transactions and create outputs
        for (Protos.Wallet.Transaction txProto : walletProto.getTransactionList()) {
            serializer.readTransaction(txProto, params, store);
        }

        // Create transactions inputs pointing to transactions
        for (Protos.Wallet.Transaction txProto : walletProto.getTransactionList()) {
            serializer.connectTransactionInputs(txProto, params);
        }
        
        // Update transaction outputs to point to inputs that spend them
        for (Protos.Wallet.Transaction txProto : walletProto.getTransactionList()) {
            WalletTransaction wtx = serializer.connectTransactionOutputs(txProto, params);
            wallet.addWalletTransaction(wtx);
        }
        
        return wallet;
    }


    private void readTransaction(Protos.Wallet.Transaction txProto,
            NetworkParameters params, BlockStore store) throws BlockStoreException {
        Transaction tx = new Transaction(params, new Sha256Hash(txProto.getHash().toByteArray()));
        if (txProto.hasUpdatedAt())
            tx.setUpdateTime(new Date(txProto.getUpdatedAt()));
        
        for (Protos.Wallet.Transaction.TransactionOutput outputProto :
            txProto.getTransactionOutputList()) {
            TransactionOutput output = new TransactionOutput(params, tx,
                    BigInteger.valueOf(outputProto.getValue()),
                    outputProto.getScriptBytes().toByteArray());
            tx.addOutput(output);
        }

        if (txMap.containsKey(tx.getHash())) {
            throw new RuntimeException("Transaction " + tx.getHashAsString() + " appears twice");
        }
        
        for (ByteString blockHash : txProto.getBlockHashList()) {
            tx.addBlockAppearance(store.get(new Sha256Hash(blockHash.toByteArray())), false);
        }
        
        txMap.put(txProto.getHash(), tx);
    }

    private void connectTransactionInputs(Protos.Wallet.Transaction txProto, NetworkParameters params) {
        Transaction tx = txMap.get(txProto.getHash());
        for (Protos.Wallet.Transaction.TransactionInput transactionInput : txProto.getTransactionInputList()) {
            TransactionInput input =
                    new TransactionInput(params, tx,
                            transactionInput.getScriptBytes().toByteArray(),
                            new TransactionOutPoint(params,
                                    transactionInput.getTransactionOutPointIndex(),
                                    txMap.get(transactionInput.getTransactionOutPointHash())
                                    )
                            );
            tx.addInput(input);
        }
    }

    private WalletTransaction connectTransactionOutputs(
            org.bitcoinj.wallet.Protos.Wallet.Transaction txProto, NetworkParameters params) {
        Transaction tx = txMap.get(txProto.getHash());
        WalletTransaction.Pool pool =
                WalletTransaction.Pool.valueOf(txProto.getPool().getNumber());
        for (int i = 0 ; i < tx.getOutputs().size() ; i++) {
            TransactionOutput output = tx.getOutputs().get(i);
            final Protos.Wallet.Transaction.TransactionOutput transactionOutput =
                    txProto.getTransactionOutput(i);
            if (transactionOutput.hasSpentByTransactionHash()) {
                Transaction spendingTx =
                    txMap.get(transactionOutput.getSpentByTransactionHash());
                final int spendingIndex = transactionOutput.getSpentByTransactionIndex();
                output.markAsSpent(spendingTx.getInputs().get(spendingIndex));
            }
        }

        return new WalletTransaction(pool, tx);
    }
}
