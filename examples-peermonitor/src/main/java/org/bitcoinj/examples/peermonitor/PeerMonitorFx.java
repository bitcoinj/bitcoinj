package org.bitcoinj.examples.peermonitor;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Network;
import org.bitcoinj.core.AddressMessage;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.utils.BriefLogFormatter;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class PeerMonitorFx extends Application {

    private static BitcoinNetwork bitcoinNetwork;
    private PeerGroup peerGroup;
    private ScheduledExecutorService executorService;
    private final Executor reverseDnsThreadPool = Executors.newCachedThreadPool();
    private final ConcurrentHashMap<Peer, String> reverseDnsLookups = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Peer, AddressMessage> addressMessages = new ConcurrentHashMap<>();
    private TableView<PeerData> peerTable;
    private Spinner<Integer> numPeersSpinner;

    public static void main(String[] args) {
        BriefLogFormatter.init();

        if (args.length == 1) {
            if (BitcoinNetwork.fromString(args[0]).isEmpty()) {
                System.err.println("Invalid peer network: " + args[0]);
                Runtime.getRuntime().exit(1);
            }
        }

        bitcoinNetwork =  (args.length == 1)
                ? BitcoinNetwork.fromString(args[0]).orElseThrow()
                : BitcoinNetwork.MAINNET;
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        setupNetwork(bitcoinNetwork);

        primaryStage.setTitle("BitcoinJ Peer Monitor");

        BorderPane root = new BorderPane();

        // Top controls: Spinner for number of peers
        HBox topControls = new HBox();
        topControls.setSpacing(10);
        topControls.setPadding(new Insets(15, 12, 15, 12));

        Label instructions = new Label("Number of peers to connect to:");
        numPeersSpinner = new Spinner<>(0, 100, 4);
        numPeersSpinner.valueProperty().addListener((obs, oldValue, newValue) -> peerGroup.setMaxConnections(newValue));

        topControls.getChildren().addAll(instructions, numPeersSpinner);

        // Center: Table view for peers
        peerTable = new TableView<>();
        peerTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

        setupPeerTable();
        root.setTop(topControls);
        root.setCenter(peerTable);

        // Scene and stage setup
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setScene(scene);
//        primaryStage.setOnCloseRequest(event -> {
//            System.out.println("Shutting down...");
//            peerGroup.stop();
//            System.out.println("Shutdown complete.");
//            Platform.exit();
//        });
        primaryStage.show();

        var started = peerGroup.startAsync();
        started.join();
        executorService = startPeerTableUpdater();
    }

    @Override
    public void stop() throws InterruptedException {
        executorService.shutdown();
        executorService.awaitTermination(10, TimeUnit.SECONDS);
        var stopped = peerGroup.stopAsync().orTimeout(10, TimeUnit.SECONDS);
        stopped.join();
        // Forcibly terminate the JVM because Orchid likes to spew non-daemon threads everywhere.
        Runtime.getRuntime().exit(0);
    }


    private void setupNetwork(BitcoinNetwork network) {
        peerGroup = new PeerGroup(network, null);
        peerGroup.setUserAgent("PeerMonitorFX", "1.0");
        peerGroup.setMaxConnections(4);
        peerGroup.addPeerDiscovery(new DnsDiscovery(network));
        peerGroup.addConnectedEventListener((peer, peerCount) -> {
            Platform.runLater(this::updatePeerTable);
            lookupReverseDNS(peer);
            getAddr(peer);
        });
        peerGroup.addDisconnectedEventListener((peer, peerCount) -> {
            Platform.runLater(this::updatePeerTable);
            reverseDnsLookups.remove(peer);
            addressMessages.remove(peer);
        });
    }

    private void lookupReverseDNS(Peer peer) {
        getHostName(peer.getAddress()).thenAccept(reverseDns -> {
            reverseDnsLookups.put(peer, reverseDns);
            Platform.runLater(this::updatePeerTable);
        });
    }

    private void getAddr(Peer peer) {
        peer.getAddr().orTimeout(15, java.util.concurrent.TimeUnit.SECONDS).whenComplete((addressMessage, e) -> {
            if (addressMessage != null) {
                addressMessages.put(peer, addressMessage);
                Platform.runLater(this::updatePeerTable);
            } else {
                e.printStackTrace();
            }
        });
    }

    private CompletableFuture<String> getHostName(PeerAddress peerAddress) {
        if (peerAddress.getAddr() != null) {
            return CompletableFuture.supplyAsync(peerAddress.getAddr()::getCanonicalHostName, reverseDnsThreadPool);
        } else if (peerAddress.getHostname() != null) {
            return CompletableFuture.completedFuture(peerAddress.getHostname());
        } else {
            return CompletableFuture.completedFuture("-unavailable-");
        }
    }

    private void setupPeerTable() {
        TableColumn<PeerData, String> addressColumn = new TableColumn<>("Address");
        addressColumn.setCellValueFactory(new PropertyValueFactory<>("address"));

        TableColumn<PeerData, String> userAgentColumn = new TableColumn<>("User Agent");
        userAgentColumn.setCellValueFactory(new PropertyValueFactory<>("userAgent"));

        TableColumn<PeerData, Long> chainHeightColumn = new TableColumn<>("Chain height");
        chainHeightColumn.setCellValueFactory(new PropertyValueFactory<>("chainHeight"));

        TableColumn<PeerData, String> protocolVersionColumn = new TableColumn<>("Protocol Version");
        protocolVersionColumn.setCellValueFactory(new PropertyValueFactory<>("protocolVersion"));

        TableColumn<PeerData, String> feeFilterColumn = new TableColumn<>("Fee Filter");
        feeFilterColumn.setCellValueFactory(new PropertyValueFactory<>("feeFilter"));

        TableColumn<PeerData, String> pingTimeColumn = new TableColumn<>("Ping Time");
        pingTimeColumn.setCellValueFactory(new PropertyValueFactory<>("pingTime"));

        TableColumn<PeerData, String> lastPingTimeColumn = new TableColumn<>("Last Ping Time");
        lastPingTimeColumn.setCellValueFactory(new PropertyValueFactory<>("lastPingTime"));

        TableColumn<PeerData, String> addressesColumn = new TableColumn<>("Peer Addresses");
        addressesColumn.setCellValueFactory(new PropertyValueFactory<>("addresses"));

        peerTable.getColumns().addAll(addressColumn, userAgentColumn, chainHeightColumn, protocolVersionColumn, feeFilterColumn, pingTimeColumn, lastPingTimeColumn, addressesColumn);
    }

    private void updatePeerTable() {
        List<Peer> connectedPeers = peerGroup.getConnectedPeers();
        List<PeerData> peerDataList = connectedPeers
                .stream()
                .map(peer -> {
                    String address = reverseDnsLookups.getOrDefault(peer, peer.getAddress().toString());
                    String userAgent = peer.getPeerVersionMessage().subVer;
                    long chainHeight = peer.getBestHeight();
                    String protocolVersion = Integer.toString(peer.getPeerVersionMessage().clientVersion);
                    Coin feeFilter = peer.getFeeFilter();
                    String feeFilterStr = feeFilter != null ? feeFilter.toFriendlyString() : "";
                    long pingTime = peer.pingInterval().map(Duration::toMillis).orElse(0L);
                    long lastPingTime = peer.lastPingInterval().map(Duration::toMillis).orElse(0L);
                    String addresses = addressMessages.containsKey(peer) ? addressMessages.get(peer).toString() : "-unavailable-";
                    return new PeerData(address, userAgent, chainHeight, protocolVersion, feeFilterStr, pingTime, lastPingTime, addresses);
                })
                .toList();
        Platform.runLater(() -> peerTable.getItems().setAll(peerDataList));
    }

    private ScheduledExecutorService startPeerTableUpdater() {
        ScheduledExecutorService executorService = Executors.newScheduledThreadPool(1);
        executorService.scheduleAtFixedRate(this::updatePeerTable, 0, 1, TimeUnit.SECONDS);
        return executorService;
    }

    public static class PeerData {
        private final SimpleStringProperty address;
        private final SimpleStringProperty userAgent;
        private final SimpleStringProperty chainHeight;
        private final SimpleStringProperty protocolVersion;
        private final SimpleStringProperty feeFilter;
        private final SimpleStringProperty pingTime;
        private final SimpleStringProperty lastPingTime;
        private final SimpleStringProperty addresses;

        public PeerData(String address, String userAgent, long chainHeight, String protocolVersion, String feeFilter, long pingTime, long lastPingTime, String addresses) {
            this.address = new SimpleStringProperty(address);
            this.userAgent = new SimpleStringProperty(userAgent);
            this.chainHeight = new SimpleStringProperty(Long.toString(chainHeight));
            this.protocolVersion = new SimpleStringProperty(protocolVersion);
            this.feeFilter = new SimpleStringProperty(feeFilter);
            this.pingTime = new SimpleStringProperty(Long.toString(pingTime));
            this.lastPingTime = new SimpleStringProperty(Long.toString(lastPingTime));
            this.addresses = new SimpleStringProperty(addresses);
        }

        public String getAddress() {
            return address.get();
        }

        public String getUserAgent() {
            return userAgent.get();
        }

        public String getChainHeight() {
            return chainHeight.get();
        }

        public String getProtocolVersion() {
            return protocolVersion.get();
        }

        public String getFeeFilter() {
            return feeFilter.get();
        }

        public String getPingTime() {
            return pingTime.get();
        }

        public String getLastPingTime() {
            return lastPingTime.get();
        }

        public String getAddresses() {
            return addresses.get();
        }
    }
}
