package org.bitcoinj.test.integration.peer;


import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.Ping;
import org.bitcoinj.core.Services;
import org.bitcoinj.core.VersionMessage;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStoreException;
import org.jspecify.annotations.NonNull;
import org.junit.After;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * Test the TestWithNetworkConnections class
 * <p>
 * This test uses the JUnit Jupiter API (JUnit 5+)
 */
@Disabled("This test currently works standalone, but causes other tests to fail with 'address in use'")
public class TestWithNetworkConnectionsTest {
    private static final Logger log = LoggerFactory.getLogger(TestWithNetworkConnectionsTest.class);

    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private final int OTHER_PEER_CHAIN_HEIGHT = 110;

    @NonNull
    private final TestWithNetworkConnections testSupport;

    TestWithNetworkConnectionsTest() {
        testSupport = new TestWithNetworkConnections(TestWithNetworkConnections.ClientType.NIO_CLIENT_MANAGER);
    }

    @AfterEach
    public void tearDown() {
        log.warn("in teardown");
        testSupport.tearDown();
    }

    @Test
    public void startStopTest() throws BlockStoreException, IOException {
        var testSupport = new TestWithNetworkConnections(TestWithNetworkConnections.ClientType.NIO_CLIENT_MANAGER);
        testSupport.setUp();
    }

    @Test
    public void pingTest() throws BlockStoreException, IOException, ExecutionException, InterruptedException {
        var testSupport = new TestWithNetworkConnections(TestWithNetworkConnections.ClientType.NIO_CLIENT_MANAGER);
        testSupport.setUp();

        Thread.sleep(1_000);

        VersionMessage ver = new VersionMessage(TESTNET, 100);
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), TestWithNetworkConnections.TCP_PORT_BASE);
        Peer peer = new Peer(TESTNET, ver, PeerAddress.simple(address), testSupport.blockChain);
        peer.addWallet(testSupport.wallet);
        VersionMessage peerVersion = new VersionMessage(TESTNET, OTHER_PEER_CHAIN_HEIGHT);
        peerVersion.clientVersion = 70001;
        peerVersion.localServices = Services.of(Services.NODE_NETWORK);
        InboundMessageQueuer writeTarget;
        try {
            writeTarget = testSupport.connect(peer, peerVersion);
        } catch (Exception exception) {
            peer.close();
            testSupport.tearDown();
            throw exception;
        }
        TimeUtils.setMockClock();
        // No ping pong happened yet.
        Assertions.assertFalse(peer.lastPingInterval().isPresent());
        Assertions.assertFalse(peer.pingInterval().isPresent());
        CompletableFuture<Duration> future = peer.sendPing();
        Assertions.assertFalse(peer.lastPingInterval().isPresent());
        Assertions.assertFalse(peer.pingInterval().isPresent());
        Assertions.assertFalse(future.isDone());
        Ping pingMsg1 = (Ping) testSupport.outbound(writeTarget);
        Assertions.assertNotNull(pingMsg1);
        TimeUtils.rollMockClock(Duration.ofSeconds(5));
        // The pong is returned.
        testSupport.inbound(writeTarget, pingMsg1.pong());
        testSupport.pingAndWait(writeTarget);
        Assertions.assertTrue(future.isDone());
        Duration elapsed = future.get();
        Assertions.assertTrue(elapsed.toMillis() > 1000, elapsed.toMillis() + " ms");
        Assertions.assertEquals(elapsed, peer.lastPingInterval().get());
        Assertions.assertEquals(elapsed, peer.pingInterval().get());
        // Do it again and make sure it affects the average.
        CompletableFuture<Duration> future2 = peer.sendPing();
        Ping pingMsg2 = (Ping) testSupport.outbound(writeTarget);
        Assertions.assertNotNull(pingMsg2);
        TimeUtils.rollMockClock(Duration.ofSeconds(50));
        testSupport.inbound(writeTarget, pingMsg2.pong());
        Duration elapsed2 = future2.get();
        Assertions.assertEquals(elapsed2, peer.lastPingInterval().get());
        //Assertions.assertEquals(Duration.ofMillis(7250), peer.pingInterval().get());
        TimeUtils.clearMockClock();

        testSupport.tearDown();
    }

}
