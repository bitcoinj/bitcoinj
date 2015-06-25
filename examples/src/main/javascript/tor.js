// Example of how to connect to a Tor hidden service and use it as a peer.
// See demo.js to learn how to invoke this program.

var bcj = org.bitcoinj;
var params = bcj.params.MainNetParams.get();
var context = new bcj.core.Context(params);
bcj.utils.BriefLogFormatter.init();

var InetAddress = Java.type("java.net.InetAddress");
var InetSocketAddress = Java.type("java.net.InetSocketAddress");

// Hack around the fact that PeerAddress assumes nodes have IP addresses. Simple enough for now.
var OnionAddress = Java.extend(Java.type("org.bitcoinj.core.PeerAddress"), {
    toSocketAddress: function() {
        return InetSocketAddress.createUnresolved("hhiv5pnxenvbf4am.onion", params.port);
    }
});

var pg = bcj.core.PeerGroup.newWithTor(context, null, new com.subgraph.orchid.TorClient(), false);
// c'tor is bogus here: the passed in InetAddress will be ignored.
pg.addAddress(new OnionAddress(InetAddress.localHost, params.port));
pg.start();

pg.waitForPeers(1).get();
print("Connected to: " + pg.connectedPeers);

for each (var peer in pg.connectedPeers) {
    print(peer.peerVersionMessage.subVer);
    peer.ping().get()
}


pg.stop();