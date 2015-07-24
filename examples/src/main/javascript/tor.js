// Example of how to connect to a Tor hidden service and use it as a peer.
// See demo.js to learn how to invoke this program.

var bcj = org.bitcoinj;
var params = bcj.params.MainNetParams.get();
var context = new bcj.core.Context(params);
bcj.utils.BriefLogFormatter.init();

var PeerAddress = Java.type("org.bitcoinj.core.PeerAddress");
var InetSocketAddress = Java.type("java.net.InetSocketAddress");

// The PeerAddress class can now handle InetSocketAddresses with hostnames if they are .onion.
var OnionAddress = InetSocketAddress.createUnresolved("hhiv5pnxenvbf4am.onion", params.port);

var pg = bcj.core.PeerGroup.newWithTor(context, null, new com.subgraph.orchid.TorClient(), false);

pg.addAddress(new PeerAddress(OnionAddress));
pg.start();

pg.waitForPeers(1).get();
print("Connected to: " + pg.connectedPeers);

for each (var peer in pg.connectedPeers) {
    print(peer.peerVersionMessage.subVer);
    peer.ping().get()
}

pg.stop();