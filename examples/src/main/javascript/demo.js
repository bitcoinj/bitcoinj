// This file shows how to use bitcoinj from Javascript.
// To run, grab the bitcoinj bundled JAR and then do something like this:
//
//   jjs -cp bitcoinj-0.12-bundled.jar demo.js
//
// This will run this file using the Nashorn Javascript engine, which is not quite as fast as V8 but still very
// competitive, speed wise. You can also get a repl/interpreter by doing this:
//
//   jjs -cp bitcoinj-0.12-bundled.jar
//
// and then you can play around in the interpreter.
//
// You will get a warning message from slf4j saying it doesn't know how you want logging to work, but you can ignore
// that for now. If you want to get rid of it, load one of the slf4j logging backends too. If you compiled from source
// then Maven already downloaded it for you here:
//
//   $HOME/.m2/repository/org/slf4j/slf4j-jdk14/1.7.6/slf4j-jdk14-1.7.6.jar
//
// or you can get it from the web here:
//
//   http://central.maven.org/maven2/org/slf4j/slf4j-jdk14/1.7.7/slf4j-jdk14-1.7.7.jar
//
// Then do:
//
//   export slf4j=/path/to/slf4j-jdk14-1.7.7.jar
//
//   jjs -cp bitcoinj-0.12-bundled.jar:$slf4fj demo.js
//
// Nashorn implements a slightly extended form of Javascript, you can learn the details of the java interop here:
//
//   http://docs.oracle.com/javase/8/docs/technotes/guides/scripting/nashorn/api.html
//
// It's pretty straightforward.


// Import some stuff.
var bcj = org.bitcoinj;
var ECKey = bcj.core.ECKey;

// We'll use the testnet for now.
var params = bcj.params.TestNet3Params.get();

// Most basic operation: make a key and print its address form to the screen.
var key = new ECKey();
print(key.toAddress(params));

// Keys record their creation time. Java getFoo()/setFoo() style methods can be treated as js properties:
print(key.creationTimeSeconds);
key.creationTimeSeconds = 0;

// The default logging output format when using JDK logging is a bit verbose (two lines per log entry!), so let's
// fix that here to be a bit more compact.
bcj.utils.BriefLogFormatter.init();

// Let's connect to the network. This won't download the block chain.
var PeerGroup = bcj.core.PeerGroup;
var pg = new PeerGroup(params)
pg.addPeerDiscovery(new bcj.net.discovery.DnsDiscovery(params));
pg.start();

// Wait until we have at least three peers.
print("Waiting for some peers")
pg.waitForPeers(3).get()
print("Connected to: " + pg.connectedPeers);

// Let's print out their subVer (sort of like an http user agent). connectedPeers is a Java collection which can be
// treated like a Javascript array. Nashorn implements a small extension to Javascript to make iteration easier, the
// "for each" construct:
var connectedPeers = pg.connectedPeers;
for each (var peer in connectedPeers)
    print(peer.peerVersionMessage.subVer);

// which for me outputs this:
// /Satoshi:0.9.99/
// /Satoshi:0.9.2/
// /Satoshi:0.9.1/

// Of course we can do it the old JS way too:
for (var i = 0; i < connectedPeers.length; i++) {
    print("Chain height for " + connectedPeers[i] + " is " + connectedPeers[i].bestHeight)
}

// or slightly more modern js:
connectedPeers.forEach(function(peer) {
    peer.ping().get();
    print("Ping time for " + peer + " is " + peer.lastPingTime);

    // The get() call above forced the program to wait for the ping. Peers are pinged in the background and the ping
    // times averaged, but if we didn't wait here we might not get a realistic ping time back because the program only
    // just started up.
});

// Nashorn, unlike V8, is thread safe (because it runs on the JVM). And bitcoinj is a threaded library. This means you
// can freely run code in parallel and mix and match concurrent constructs to use your preferred style. Above we used
// blocking code. This is convenient in scripts and so on, but sometimes we want to keep the main thread free. Let's
// do the same thing but in an async style:

var futures = [];
connectedPeers.forEach(function(peer) {
    var future = peer.ping();
    futures.push(future);

    // A "future" is sometimes called a promise. This construct says: run the closure on the "user thread" when the
    // future completes. We can get the result using future.get() which won't block because we know it's now ready.
    // The user thread is a thread that sits around waiting for closures to be given to it and then runs them in
    // sequence. So by specifying USER_THREAD here we know the closure cannot run in parallel. We could ask the
    // closure to run on other threads too, if we wanted, e.g. the JavaFX UI thread if making a GUI app.
    future.addListener(function() {
        var pingTime = future.get();
        print("Async callback ping time for " + peer + " is " + pingTime);
    }, bcj.utils.Threading.USER_THREAD);
});

// Just wait for all the pings here by calling get again ...
futures.forEach(function(f) { f.get() });
print("Done!");


