/*
 * Copyright 2012 Matt Corallo.
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

package org.bitcoinj.testing;

import org.bitcoinj.core.*;
import org.bitcoinj.net.BlockingClientManager;
import org.bitcoinj.net.NioClientManager;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import com.google.common.base.Preconditions;

import java.net.InetSocketAddress;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

/**
 * Utility class that makes it easy to work with mock NetworkConnections in PeerGroups.
 */
public class TestWithPeerGroup extends TestWithNetworkConnections {
    protected static final NetworkParameters params = UnitTestParams.get();
    protected PeerGroup peerGroup;

    protected VersionMessage remoteVersionMessage;
    private final ClientType clientType;

    public TestWithPeerGroup(ClientType clientType) {
        super(clientType);
        if (clientType != ClientType.NIO_CLIENT_MANAGER && clientType != ClientType.BLOCKING_CLIENT_MANAGER)
            throw new RuntimeException();
        this.clientType = clientType;
    }

    @Override
    public void setUp() throws Exception {
        setUp(new MemoryBlockStore(params));
    }

    @Override
    public void setUp(BlockStore blockStore) throws Exception {
        super.setUp(blockStore);

        remoteVersionMessage = new VersionMessage(unitTestParams, 1);
        remoteVersionMessage.localServices = VersionMessage.NODE_NETWORK;
        remoteVersionMessage.clientVersion = NotFoundMessage.MIN_PROTOCOL_VERSION;
        initPeerGroup();
    }

    @Override
    public void tearDown() {
        try {
            super.tearDown();
            Utils.finishMockSleep();
            peerGroup.stopAsync();
            peerGroup.awaitTerminated();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected void initPeerGroup() {
        if (clientType == ClientType.NIO_CLIENT_MANAGER)
            peerGroup = new PeerGroup(unitTestParams, blockChain, new NioClientManager());
        else
            peerGroup = new PeerGroup(unitTestParams, blockChain, new BlockingClientManager());
        peerGroup.setPingIntervalMsec(0);  // Disable the pings as they just get in the way of most tests.
        peerGroup.addWallet(wallet);
    }

    protected InboundMessageQueuer connectPeerWithoutVersionExchange(int id) throws Exception {
        Preconditions.checkArgument(id < PEER_SERVERS);
        InetSocketAddress remoteAddress = new InetSocketAddress("127.0.0.1", 2000 + id);
        Peer peer = peerGroup.connectTo(remoteAddress).getConnectionOpenFuture().get();
        InboundMessageQueuer writeTarget = newPeerWriteTargetQueue.take();
        writeTarget.peer = peer;
        return writeTarget;
    }
    
    protected InboundMessageQueuer connectPeer(int id) throws Exception {
        return connectPeer(id, remoteVersionMessage);
    }

    protected InboundMessageQueuer connectPeer(int id, VersionMessage versionMessage) throws Exception {
        checkArgument(versionMessage.hasBlockChain());
        InboundMessageQueuer writeTarget = connectPeerWithoutVersionExchange(id);
        // Complete handshake with the peer - send/receive version(ack)s, receive bloom filter
        writeTarget.sendMessage(versionMessage);
        writeTarget.sendMessage(new VersionAck());
        stepThroughInit(versionMessage, writeTarget);
        return writeTarget;
    }

    // handle peer discovered by PeerGroup
    protected InboundMessageQueuer handleConnectToPeer(int id) throws Exception {
        return handleConnectToPeer(id, remoteVersionMessage);
    }

    // handle peer discovered by PeerGroup
    protected InboundMessageQueuer handleConnectToPeer(int id, VersionMessage versionMessage) throws Exception {
        InboundMessageQueuer writeTarget = newPeerWriteTargetQueue.take();
        checkArgument(versionMessage.hasBlockChain());
        // Complete handshake with the peer - send/receive version(ack)s, receive bloom filter
        writeTarget.sendMessage(versionMessage);
        writeTarget.sendMessage(new VersionAck());
        stepThroughInit(versionMessage, writeTarget);
        return writeTarget;
    }

    private void stepThroughInit(VersionMessage versionMessage, InboundMessageQueuer writeTarget) throws InterruptedException {
        checkState(writeTarget.nextMessageBlocking() instanceof VersionMessage);
        checkState(writeTarget.nextMessageBlocking() instanceof VersionAck);
        if (versionMessage.isBloomFilteringSupported()) {
            checkState(writeTarget.nextMessageBlocking() instanceof BloomFilter);
            checkState(writeTarget.nextMessageBlocking() instanceof MemoryPoolMessage);
        }
    }
}
