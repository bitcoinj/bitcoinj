/*
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

package com.google.bitcoin.examples;

import com.google.bitcoin.core.AbstractPeerEventListener;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Peer;
import com.google.bitcoin.core.PeerGroup;
import com.google.bitcoin.discovery.DnsDiscovery;
import com.google.bitcoin.utils.BriefLogFormatter;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;

/**
 * Shows connected peers in a table view, so you can watch as they come and go.
 */
public class PeerMonitor {
    private NetworkParameters params;
    private PeerGroup peerGroup;
    private PeerTableModel peerTableModel;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        new PeerMonitor();
    }

    public PeerMonitor() {
        setupNetwork();
        setupGUI();
    }

    private void setupNetwork() {
        params = NetworkParameters.prodNet();
        peerGroup = new PeerGroup(params, null /* no chain */);
        peerGroup.setUserAgent("PeerMonitor", "1.0");
        peerGroup.addPeerDiscovery(new DnsDiscovery(params));
        peerGroup.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerConnected(Peer peer, int peerCount) {
                refreshUI();
            }

            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                refreshUI();
            }
        });
        peerGroup.start();
    }

    private void refreshUI() {
        // Tell the Swing UI thread to redraw the peers table.
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                peerTableModel.fireTableDataChanged();
            }
        });
    }

    private void setupGUI() {
        JFrame window = new JFrame("Network monitor");
        window.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        JLabel instructions = new JLabel("Peers shown below. Download peer is in bold.");
        window.getContentPane().add(instructions, BorderLayout.NORTH);
        peerTableModel = new PeerTableModel();
        JTable peerTable = new JTable(peerTableModel);
        JScrollPane scrollPane = new JScrollPane(peerTable);
        window.getContentPane().add(scrollPane, BorderLayout.CENTER);
        window.pack();
        window.setSize(640, 480);
        window.setVisible(true);
    }

    private class PeerTableModel extends AbstractTableModel {
        private final int IP_ADDRESS = 0;
        private final int PROTOCOL_VERSION = 1;
        private final int USER_AGENT = 2;
        private final int CHAIN_HEIGHT = 3;

        public int getRowCount() {
            return peerGroup.numConnectedPeers();
        }

        @Override
        public String getColumnName(int i) {
            switch (i) {
                case IP_ADDRESS: return "IP address";
                case PROTOCOL_VERSION: return "Protocol version";
                case USER_AGENT: return "User Agent";
                case CHAIN_HEIGHT: return "Chain height";
                default: throw new RuntimeException();
            }
        }

        public int getColumnCount() {
            return 4;
        }

        public Object getValueAt(int row, int col) {
            List<Peer> peers = peerGroup.getConnectedPeers();
            Peer peer = peers.get(row);
            switch (col) {
                case IP_ADDRESS:
                    return peer.getAddress().getAddr().getHostAddress();
                case PROTOCOL_VERSION:
                    return Integer.toString(peer.getPeerVersionMessage().clientVersion);
                case USER_AGENT:
                    return peer.getPeerVersionMessage().subVer;
                case CHAIN_HEIGHT:
                    return peer.getBestHeight();

                default: throw new RuntimeException();
            }
        }
    }
}
