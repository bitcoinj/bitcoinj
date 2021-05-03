/*
 * Copyright 2012 Google Inc.
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

package org.bitcoinj.examples;

import org.bitcoinj.core.AddressMessage;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.utils.BriefLogFormatter;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Shows connected peers in a table view, so you can watch as they come and go.
 */
public class PeerMonitor {
    private NetworkParameters params;
    private PeerGroup peerGroup;
    private PeerTableModel peerTableModel;
    private PeerTableRenderer peerTableRenderer;

    private final HashMap<Peer, String> reverseDnsLookups = new HashMap<>();
    private final HashMap<Peer, AddressMessage> addressMessages = new HashMap<>();

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        new PeerMonitor();
    }

    public PeerMonitor() {
        setupNetwork();
        setupGUI();
        peerGroup.startAsync();
    }

    private void setupNetwork() {
        params = MainNetParams.get();
        peerGroup = new PeerGroup(params, null /* no chain */);
        peerGroup.setUserAgent("PeerMonitor", "1.0");
        peerGroup.setMaxConnections(4);
        peerGroup.addPeerDiscovery(new DnsDiscovery(params));
        peerGroup.addConnectedEventListener((peer, peerCount) -> {
            refreshUI();
            lookupReverseDNS(peer);
            getAddr(peer);
        });
        peerGroup.addDisconnectedEventListener((peer, peerCount) -> {
            refreshUI();
            synchronized (reverseDnsLookups) {
                reverseDnsLookups.remove(peer);
            }
            synchronized (addressMessages) {
                addressMessages.remove(peer);
            }
        });
    }

    private void lookupReverseDNS(final Peer peer) {
        new Thread(() -> {
            // This can take a looooong time.
            String reverseDns = peer.getAddress().getAddr().getCanonicalHostName();
            synchronized (reverseDnsLookups) {
                reverseDnsLookups.put(peer, reverseDns);
            }
            refreshUI();
        }).start();
    }

    private void getAddr(final Peer peer) {
        new Thread(() -> {
            try {
                AddressMessage addressMessage = peer.getAddr().get(15, TimeUnit.SECONDS);
                synchronized (addressMessages) {
                    addressMessages.put(peer, addressMessage);
                }
                refreshUI();
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                e.printStackTrace();
            }
        }).start();
    }

    private void refreshUI() {
        // Tell the Swing UI thread to redraw the peers table.
        SwingUtilities.invokeLater(() -> peerTableModel.updateFromPeerGroup());
    }

    private void setupGUI() {
        JFrame window = new JFrame("Network monitor");
        window.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        window.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent windowEvent) {
                System.out.println("Shutting down ...");
                peerGroup.stop();
                System.out.println("Shutdown complete.");
                System.exit(0);
            }
        });

        JPanel panel = new JPanel();
        JLabel instructions = new JLabel("Number of peers to connect to: ");
        final SpinnerNumberModel spinnerModel = new SpinnerNumberModel(4, 0, 100, 1);
        spinnerModel.addChangeListener(changeEvent -> peerGroup.setMaxConnections(spinnerModel.getNumber().intValue()));
        JSpinner numPeersSpinner = new JSpinner(spinnerModel);
        panel.add(instructions);
        panel.add(numPeersSpinner);
        window.getContentPane().add(panel, BorderLayout.NORTH);

        peerTableModel = new PeerTableModel();
        JTable peerTable = new JTable(peerTableModel);
        peerTable.setAutoCreateRowSorter(true);
        peerTableRenderer = new PeerTableRenderer(peerTableModel);
        peerTable.setDefaultRenderer(String.class, peerTableRenderer);
        peerTable.setDefaultRenderer(Integer.class, peerTableRenderer);
        peerTable.setDefaultRenderer(Long.class, peerTableRenderer);
        TableColumnModel columnModel = peerTable.getColumnModel();
        columnModel.getColumn(PeerTableModel.IP_ADDRESS).setPreferredWidth(300);
        columnModel.getColumn(PeerTableModel.USER_AGENT).setPreferredWidth(150);
        columnModel.getColumn(PeerTableModel.FEE_FILTER).setPreferredWidth(150);
        columnModel.getColumn(PeerTableModel.ADDRESSES).setPreferredWidth(400);

        JScrollPane scrollPane = new JScrollPane(peerTable);
        window.getContentPane().add(scrollPane, BorderLayout.CENTER);
        window.pack();
        window.setSize(1280, 768);
        window.setVisible(true);

        // Refresh the UI every half second to get the latest ping times. The event handler runs in the UI thread.
        new Timer(1000, actionEvent -> peerTableModel.updateFromPeerGroup()).start();
    }

    private class PeerTableModel extends AbstractTableModel {
        public static final int IP_ADDRESS = 0;
        public static final int PROTOCOL_VERSION = 1;
        public static final int USER_AGENT = 2;
        public static final int CHAIN_HEIGHT = 3;
        public static final int FEE_FILTER = 4;
        public static final int PING_TIME = 5;
        public static final int LAST_PING_TIME = 6;
        public static final int ADDRESSES = 7;

        public List<Peer> connectedPeers = new ArrayList<>();
        public List<Peer> pendingPeers = new ArrayList<>();

        public void updateFromPeerGroup() {
            connectedPeers = peerGroup.getConnectedPeers();
            pendingPeers = peerGroup.getPendingPeers();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return connectedPeers.size() + pendingPeers.size();
        }

        @Override
        public String getColumnName(int i) {
            switch (i) {
                case IP_ADDRESS: return "Address";
                case PROTOCOL_VERSION: return "Protocol version";
                case USER_AGENT: return "User Agent";
                case CHAIN_HEIGHT: return "Chain height";
                case FEE_FILTER: return "Fee filter (per kB)";
                case PING_TIME: return "Average ping";
                case LAST_PING_TIME: return "Last ping";
                case ADDRESSES: return "Peer addresses";
                default: throw new RuntimeException();
            }
        }

        @Override
        public int getColumnCount() {
            return 8;
        }

        @Override
        public Class<?> getColumnClass(int column) {
            switch (column) {
                case PROTOCOL_VERSION:
                    return Integer.class;
                case CHAIN_HEIGHT:
                case PING_TIME:
                case LAST_PING_TIME:
                    return Long.class;
                default:
                    return String.class;
            }
        }

        @Override
        public Object getValueAt(int row, int col) {
            if (row >= connectedPeers.size()) {
                // Peer that isn't connected yet.
                Peer peer = pendingPeers.get(row - connectedPeers.size());
                switch (col) {
                    case IP_ADDRESS:
                        return getAddressForPeer(peer);
                    case PROTOCOL_VERSION:
                        return 0;
                    case CHAIN_HEIGHT:
                    case PING_TIME:
                    case LAST_PING_TIME:
                        return 0L;
                    default:
                        return "(pending)";
                }
            }
            Peer peer = connectedPeers.get(row);
            switch (col) {
                case IP_ADDRESS:
                    return getAddressForPeer(peer);
                case PROTOCOL_VERSION:
                    return Integer.toString(peer.getPeerVersionMessage().clientVersion);
                case USER_AGENT:
                    return peer.getPeerVersionMessage().subVer;
                case CHAIN_HEIGHT:
                    return peer.getBestHeight();
                case FEE_FILTER:
                    Coin feeFilter = peer.getFeeFilter();
                    return feeFilter != null ? feeFilter.toFriendlyString() : "";
                case PING_TIME:
                    return peer.getPingTime();
                case LAST_PING_TIME:
                    return peer.getLastPingTime();
                case ADDRESSES:
                    return getAddressesForPeer(peer);

                default: throw new RuntimeException();
            }
        }

        private Object getAddressForPeer(Peer peer) {
            String s;
            synchronized (reverseDnsLookups) {
                s = reverseDnsLookups.get(peer);
            }
            if (s != null)
                return s;
            else
                return peer.getAddress().getAddr().getHostAddress();
        }

        private String getAddressesForPeer(Peer peer) {
            synchronized (addressMessages) {
                AddressMessage addressMessage = addressMessages.get(peer);
                return addressMessage != null ? addressMessage.toString() : "";
            }
        }
    }

    private class PeerTableRenderer extends JLabel implements TableCellRenderer {
        private final PeerTableModel model;
        private final Font normal, bold;

        public PeerTableRenderer(PeerTableModel model) {
            super();
            this.model = model;
            this.normal = new Font("Sans Serif", Font.PLAIN, 12);
            this.bold = new Font("Sans Serif", Font.BOLD, 12);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object contents,
                                                       boolean selected, boolean hasFocus, int row, int column) {
            row = table.convertRowIndexToModel(row);
            column = table.convertColumnIndexToModel(column);

            String str = contents.toString();
            if (model.connectedPeers == null || model.pendingPeers == null) {
                setText(str);
                return this;
            }

            if (row >= model.connectedPeers.size()) {
                setFont(normal);
                setForeground(Color.LIGHT_GRAY);
            } else {
                if (model.connectedPeers.get(row) == peerGroup.getDownloadPeer())
                    setFont(bold);
                else
                    setFont(normal);
                setForeground(Color.BLACK);

                // Mark chain heights that aren't normal but not for pending peers, as we don't know their heights yet.
                if (column == PeerTableModel.CHAIN_HEIGHT) {
                    long height = (Long) contents;
                    if (height != peerGroup.getMostCommonChainHeight()) {
                        str = height + " \u2022 ";
                    }
                }
            }

            boolean isPingColumn = column == PeerTableModel.PING_TIME || column == PeerTableModel.LAST_PING_TIME;
            if (isPingColumn && contents.equals(Long.MAX_VALUE)) {
                // We don't know the answer yet
                str = "";
            }
            setText(str);
            return this;
        }
    }
}
