/*
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.examples.toywallet;

import com.google.bitcoin.core.*;
import com.google.bitcoin.discovery.DnsDiscovery;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.params.TestNet3Params;
import com.google.bitcoin.store.H2FullPrunedBlockStore;
import com.google.bitcoin.store.SPVBlockStore;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.common.collect.Lists;
import org.spongycastle.util.encoders.Hex;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * A GUI demo that lets you watch received transactions as they accumulate confidence.
 */
public class ToyWallet {
    private NetworkParameters params;
    private Wallet wallet;
    private PeerGroup peerGroup;
    private AbstractBlockChain chain;
    private JLabel networkStats;
    private File walletFile;
    private JScrollPane txScrollPane;
    private JTable txTable;
    private TransactionTableModel txTableModel;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        new ToyWallet(true, true, args);
    }

    // Converts the contents of the wallet to a table for the GUI.
    public class TransactionTableModel extends AbstractTableModel {
        private List<Transaction> transactions = Lists.newLinkedList();

        public int getRowCount() {
            return transactions.size();
        }

        @Override
        public String getColumnName(int i) {
            switch (i) {
                case 0: return "Confidence";
                case 1: return "Description";
                case 2: return "Value";
                default: throw new RuntimeException("Unreachable");
            }
        }

        public int getColumnCount() {
            // Column 1: confidence
            // Column 2: description
            // Column 3: balance adjustment (+ve or -ve)
            return 3;
        }

        public Object getValueAt(int row, int col) {
            Transaction tx = transactions.get(row);
            switch (col) {
                case 0:
                    TransactionConfidence conf = tx.getConfidence();
                    return conf.toString();
                case 1:
                    return String.format("TX with %d inputs and %d outputs",
                            tx.getInputs().size(), tx.getOutputs().size());
                case 2:
                    try {
                        BigInteger val = tx.getValue(wallet);
                        return Utils.bitcoinValueToFriendlyString(val);
                    } catch (ScriptException e) {
                        throw new RuntimeException(e);
                    }
                default:
                    throw new RuntimeException("Unreachable");
            }
        }

        public void setTransactions(List<Transaction> txns) {
            transactions = txns;
            fireTableDataChanged();
        }
    }
    
    public ToyWallet(boolean testnet, boolean fullChain, String[] args) throws Exception {
        // Set up a Bitcoin connection + empty wallet. TODO: Simplify the setup for this use case.
        if (testnet) {
            params = TestNet3Params.get();
        } else {
            params = MainNetParams.get();
        }

        // Try to read the wallet from storage, create a new one if not possible.
        boolean freshWallet = false;
        walletFile = new File("toy.wallet");
        try {
            wallet = Wallet.loadFromFile(walletFile);
        } catch (IOException e) {
            wallet = new Wallet(params);

            // Allow user to specify the first key on the command line as:
            //   hex-encoded-key:creation-time-seconds
            ECKey key;
            if (args.length > 0) {
                try {
                    String[] parts = args[0].split(":");
                    byte[] pubKey = Hex.decode(parts[0]);
                    key = new ECKey(null, pubKey);
                    long creationTimeSeconds = Long.parseLong(parts[1]);
                    key.setCreationTimeSeconds(creationTimeSeconds);
                    System.out.println(String.format("Using address from command line %s, created on %s",
                        key.toAddress(params).toString(), new Date(creationTimeSeconds*1000).toString()));
                } catch (Exception e2) {
                    System.err.println("Could not understand argument. Try a hex encoded pub key with a creation " +
                        "time in seconds appended with a colon in between: " + e2.toString());
                    return;
                }
            } else {
                key = new ECKey();  // Generate a fresh key.
            }
            wallet.addKey(key);
            
            wallet.saveToFile(walletFile);
            freshWallet = true;
        }
        System.out.println("Send to: " + wallet.getKeys().get(0).toAddress(params));
        System.out.println(wallet);

        wallet.autosaveToFile(walletFile, 500, TimeUnit.MILLISECONDS, null);

        File blockChainFile = new File("toy.blockchain");
        if (!blockChainFile.exists() && !freshWallet) {
            // No block chain, but we had a wallet. So empty out the transactions in the wallet so when we rescan
            // the blocks there are no problems (wallets don't support replays without being emptied).
            wallet.clearTransactions(0);
        }

        if (fullChain) {
            H2FullPrunedBlockStore store = new H2FullPrunedBlockStore(params, blockChainFile.getName(), 100);
            chain = new FullPrunedBlockChain(params, wallet, store);
        } else {
            chain = new BlockChain(params, wallet, new SPVBlockStore(params, blockChainFile));
        }

        peerGroup = new PeerGroup(params, chain);
        peerGroup.setUserAgent("ToyWallet", "1.0");
        peerGroup.addPeerDiscovery(new DnsDiscovery(params));
        peerGroup.addWallet(wallet);

        // Watch for peers coming and going so we can update the UI.
        peerGroup.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerConnected(Peer peer, int peerCount) {
                super.onPeerConnected(peer, peerCount);
                triggerNetworkStatsUpdate();
            }

            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                super.onPeerDisconnected(peer, peerCount);
                triggerNetworkStatsUpdate();
            }

            @Override
            public void onBlocksDownloaded(Peer peer, Block block, int blocksLeft) {
                super.onBlocksDownloaded(peer, block, blocksLeft);
                triggerNetworkStatsUpdate();
            }
        });

        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onWalletChanged(Wallet wallet) {
                // MUST BE THREAD SAFE.
                final List<Transaction> txns = wallet.getTransactionsByTime();
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        txTableModel.setTransactions(txns);
                    }
                });
            }
        });
        
        // Create the GUI.
        JFrame window = new JFrame("Toy wallet");
        window.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setupWindow(window);
        window.pack();
        window.setSize(640, 480);

        txTableModel.setTransactions(wallet.getTransactionsByTime());

        // Go!
        window.setVisible(true);
        peerGroup.start();
        peerGroup.downloadBlockChain();
    }

    private void triggerNetworkStatsUpdate() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                int numPeers = peerGroup.numConnectedPeers();
                StoredBlock chainHead = chain.getChainHead();
                String date = chainHead.getHeader().getTime().toString();
                String status = String.format("%d peer(s) connected. %d blocks: %s",
                        numPeers, chainHead.getHeight(), date);
                networkStats.setText(status);
            }
        });
    }

    private void setupWindow(JFrame window) {
        final Address address = wallet.getKeys().get(0).toAddress(params);
        JLabel instructions = new JLabel(
                "<html>Broadcast transactions appear below. Watch them gain confidence.<br>" +
                "Send coins to: <b>" + address + "</b> <i>(click to place on clipboard)</i>");
        // Just make the label clickable so it puts the address in the clipboard.
        instructions.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent mouseEvent) {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection sel = new StringSelection(address.toString());
                clipboard.setContents(sel, sel);
            }
        });
        window.getContentPane().add(instructions, BorderLayout.NORTH);

        txTableModel = new TransactionTableModel();
        txTableModel.transactions = new LinkedList<Transaction>();
        txTable = new JTable(txTableModel);
        // The list of transactions.
        txScrollPane = new JScrollPane(txTable);
        window.getContentPane().add(txScrollPane, BorderLayout.CENTER);
        
        networkStats = new JLabel("Connecting to the Bitcoin network ...");
        window.getContentPane().add(networkStats, BorderLayout.SOUTH);
    }
}
