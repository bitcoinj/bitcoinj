/*
 * Copyright by the original author or authors.
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

// Example of how to connect to a Tor hidden service and use it as a peer.
// See demo.js to learn how to invoke this program.

var bcj = org.bitcoinj;
var params = bcj.params.MainNetParams.get();
var context = new bcj.core.Context(params);
bcj.utils.BriefLogFormatter.init();

var PeerAddress = Java.type("org.bitcoinj.core.PeerAddress");
var pg = bcj.core.PeerGroup.newWithTor(context, null, new com.subgraph.orchid.TorClient(), false);
pg.addAddress(new PeerAddress("nkf5e6b7pl4jfd4a.onion", params.port));
pg.start();

pg.waitForPeers(1).get();
print("Connected to: " + pg.connectedPeers);

for each (var peer in pg.connectedPeers) {
    print(peer.peerVersionMessage.subVer);
    peer.ping().get()
}

pg.stop();