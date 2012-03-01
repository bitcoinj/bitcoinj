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
import com.google.bitcoin.store.BoundedOverheadBlockStore;
import com.google.bitcoin.utils.BriefLogFormatter;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * A GUI demo that lets you watch received transactions as they accumulate confidence.
 */
public class ToyWallet {
    private final TxListModel txListModel = new TxListModel();
    private JList txList;
    private NetworkParameters params;
    private Wallet wallet;
    private PeerGroup peerGroup;
    private BlockChain chain;
    private JLabel networkStats;
    private File walletFile;
    private JScrollPane txScrollPane;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        new ToyWallet(false, args);
    }
    
    public ToyWallet(boolean testnet, String[] args) throws Exception {
        // Set up a Bitcoin connection + empty wallet. TODO: Simplify the setup for this use case.
        if (testnet) {
            params = NetworkParameters.testNet();
        } else {
            params = NetworkParameters.prodNet();
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
            wallet.keychain.add(key);
            
            wallet.saveToFile(walletFile);
            freshWallet = true;
        }
        System.out.println("Send to: " + wallet.keychain.get(0).toAddress(params));
        System.out.println(wallet);

        File blockChainFile = new File("toy.blockchain");
        if (!blockChainFile.exists() && !freshWallet) {
            // No block chain, but we had a wallet. So empty out the transactions in the wallet so when we rescan
            // the blocks there are no problems (wallets don't support replays without being emptied).
            wallet.clearTransactions(0);
        }
        chain = new BlockChain(params, wallet, new BoundedOverheadBlockStore(params, blockChainFile));

        peerGroup = new PeerGroup(params, chain);
        peerGroup.setUserAgent("ToyWallet", "1.0");
        if (testnet) {
            peerGroup.addAddress(new PeerAddress(InetAddress.getByName("plan99.net"), 18333));
            peerGroup.addAddress(new PeerAddress(InetAddress.getByName("localhost"), 18333));
        } else {
            peerGroup.addPeerDiscovery(new DnsDiscovery(params));
        }
        peerGroup.addWallet(wallet);
        peerGroup.setFastCatchupTimeSecs(wallet.getEarliestKeyCreationTime());

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
                handleNewBlock();
            }
        });

        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                super.onCoinsReceived(wallet, tx, prevBalance, newBalance);
                handleNewTransaction(tx);
            }

            @Override
            public void onCoinsSent(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                super.onCoinsSent(wallet, tx, prevBalance, newBalance);
                handleNewTransaction(tx);
            }

            @Override
            public void onChange() {
                try {
                    System.out.println("Wallet changed");
                    wallet.saveToFile(walletFile);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        
        // Create the GUI.
        JFrame window = new JFrame("Toy wallet");
        window.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setupWindow(window);
        window.pack();
        window.setSize(640, 480);

        // Put the transactions stored in the wallet, into the GUI.
        final Set<Transaction> walletTransactions = wallet.getTransactions(true, true);
        SwingUtilities.invokeAndWait(new Runnable() {
            public void run() {
                for (final Transaction tx : walletTransactions) {
                    txListModel.monitorTx(tx);
                }
            }
        });


        // Go!
        window.setVisible(true);
        peerGroup.start();
        peerGroup.downloadBlockChain();
    }

    private void handleNewBlock() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                txListModel.newBlock();
            }
        });
    }

    private void handleNewTransaction(final Transaction t) {
        // Running on a peer thread, switch to Swing thread before adding and updating the UI.
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                txListModel.monitorTx(t);
            }
        });
    }

    private void triggerNetworkStatsUpdate() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                int numPeers = peerGroup.numConnectedPeers();
                StoredBlock chainHead = chain.getChainHead();
                String date = chainHead.getHeader().getTime().toString();
                String plural =  numPeers > 1 ? "peers" : "peer";
                String status = String.format("%d %s connected. %d blocks: %s",
                        numPeers, plural, chainHead.getHeight(), date);
                networkStats.setText(status);
            }
        });
    }

    private void setupWindow(JFrame window) {
        JLabel instructions = new JLabel(
                "<html>Broadcast transactions appear below. Watch them gain confidence.<br>" +
                "Send coins to: <b>" + wallet.keychain.get(0).toAddress(params) + "</b>");
        window.getContentPane().add(instructions, BorderLayout.NORTH);
        
        // The list of transactions.
        txList = new JList(txListModel);
        txList.setCellRenderer(new TxListLabel());
        txList.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        txList.setLayoutOrientation(JList.VERTICAL);
        txScrollPane = new JScrollPane(txList);
        window.getContentPane().add(txScrollPane, BorderLayout.CENTER);
        
        networkStats = new JLabel("Connecting to the Bitcoin network ...");
        window.getContentPane().add(networkStats, BorderLayout.SOUTH);
    }

    // Object that manages the contents of the list view.
    private class TxListModel extends AbstractListModel {
        private List<Transaction> transactions = new ArrayList<Transaction>();

        public void monitorTx(Transaction tx) {
            assert SwingUtilities.isEventDispatchThread();
            transactions.add(tx);
            // Set up a tx confidence change event listener, so we know when to update the list.
            tx.getConfidence().addEventListener(new TransactionConfidence.Listener() {
                public void onConfidenceChanged(Transaction tx) {
                    // Note that this does NOT get called for every block that is received, just when we transition
                    // between confidence states.
                    int txIndex = transactions.indexOf(tx);
                    fireContentsChanged(this, txIndex, txIndex);
                }
            });
            fireIntervalAdded(this, transactions.size() - 1, transactions.size() - 1);
        }

        public int getSize() {
            return transactions.size();
        }

        public Object getElementAt(int i) {
            Transaction tx = transactions.get(i);
            return tx.toString() + "\n" + tx.getConfidence().toString();
        }

        public void newBlock() {
            fireContentsChanged(this, 0, getSize() - 1);
        }
    }

    private class TxListLabel extends JLabel implements ListCellRenderer {
        public Component getListCellRendererComponent(JList list, Object contents,
                                                      int index, boolean isSelected,
                                                      boolean cellHasFocus) {
            String value = (String) contents;
            final String key = wallet.keychain.get(0).toAddress(params).toString();
            value = "<html>" + value.replaceAll("\n", "<br>").replaceAll("<br> ", "<br>&nbsp;&nbsp;")
              .replaceAll(key, "<i>" + key + "</i>");
            setText(value);
            setOpaque(true);
            setBackground(index % 2 == 1 ? new Color(230, 230, 230) : Color.WHITE);
            return this;
        }
    }
}
