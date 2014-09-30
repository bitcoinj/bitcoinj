package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.TransactionBroadcaster;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.Wallet;
import org.bitcoin.paymentchannel.Protos;
import org.easymock.Capture;
import org.junit.Before;
import org.junit.Test;

import static junit.framework.TestCase.assertTrue;
import static org.bitcoin.paymentchannel.Protos.TwoWayChannelMessage;
import static org.bitcoin.paymentchannel.Protos.TwoWayChannelMessage.MessageType;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;

public class PaymentChannelServerTest {

    private static final int CLIENT_MAJOR_VERSION = 1;
    private static final long SERVER_MAJOR_VERSION = 1;
    public Wallet wallet;
    public PaymentChannelServer.ServerConnection connection;
    public PaymentChannelServer dut;
    public Capture<? extends TwoWayChannelMessage> serverVersionCapture;
    private TransactionBroadcaster broadcaster;

    @Before
    public void setUp() {
        broadcaster = createMock(TransactionBroadcaster.class);
        wallet = createMock(Wallet.class);
        connection = createMock(PaymentChannelServer.ServerConnection.class);
        serverVersionCapture = new Capture<TwoWayChannelMessage>();
        connection.sendToClient(capture(serverVersionCapture));
        Utils.setMockClock();
    }


    @Test
    public void shouldAcceptDefaultTimeWindow() {
        final TwoWayChannelMessage message = createClientVersionMessage();
        final Capture<TwoWayChannelMessage> initiateCapture = new Capture<TwoWayChannelMessage>();
        connection.sendToClient(capture(initiateCapture));
        replay(connection);

        dut = new PaymentChannelServer(broadcaster, wallet, Coin.CENT, connection);

        dut.connectionOpen();
        dut.receiveMessage(message);

        long expectedExpire = Utils.currentTimeSeconds() + 24 * 60 * 60 - 60;  // This the default defined in paymentchannel.proto
        assertServerVersion();
        assertExpireTime(expectedExpire, initiateCapture);
    }

    @Test
    public void shouldTruncateTooSmallTimeWindow() {
        final int minTimeWindow = 20000;
        final int timeWindow = minTimeWindow - 1;
        final TwoWayChannelMessage message = createClientVersionMessage(timeWindow);
        final Capture<TwoWayChannelMessage> initiateCapture = new Capture<TwoWayChannelMessage>();
        connection.sendToClient(capture(initiateCapture));

        replay(connection);
        dut = new PaymentChannelServer(broadcaster, wallet, Coin.CENT, minTimeWindow, 40000, connection);

        dut.connectionOpen();
        dut.receiveMessage(message);

        long expectedExpire = Utils.currentTimeSeconds() + minTimeWindow;
        assertServerVersion();
        assertExpireTime(expectedExpire, initiateCapture);
    }

    @Test
    public void shouldTruncateTooLargeTimeWindow() {
        final int maxTimeWindow = 40000;
        final int timeWindow = maxTimeWindow + 1;
        final TwoWayChannelMessage message = createClientVersionMessage(timeWindow);
        final Capture<TwoWayChannelMessage> initiateCapture = new Capture<TwoWayChannelMessage>();
        connection.sendToClient(capture(initiateCapture));
        replay(connection);

        dut = new PaymentChannelServer(broadcaster, wallet, Coin.CENT, 20000, maxTimeWindow, connection);

        dut.connectionOpen();
        dut.receiveMessage(message);

        long expectedExpire = Utils.currentTimeSeconds() + maxTimeWindow;
        assertServerVersion();
        assertExpireTime(expectedExpire, initiateCapture);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowTimeWindowLessThan2h() {
        dut = new PaymentChannelServer(broadcaster, wallet, Coin.CENT, 7199, 40000, connection);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNegativeTimeWindow() {
        dut = new PaymentChannelServer(broadcaster, wallet, Coin.CENT, 40001, 40000, connection);
    }

    @Test
    public void shouldAllowExactTimeWindow() {
        final TwoWayChannelMessage message = createClientVersionMessage();
        final Capture<TwoWayChannelMessage> initiateCapture = new Capture<TwoWayChannelMessage>();
        connection.sendToClient(capture(initiateCapture));
        replay(connection);
        final int expire = 24 * 60 * 60 - 60;  // This the default defined in paymentchannel.proto

        dut = new PaymentChannelServer(broadcaster, wallet, Coin.CENT, expire, expire, connection);
        dut.connectionOpen();
        long expectedExpire = Utils.currentTimeSeconds() + expire;
        dut.receiveMessage(message);

        assertServerVersion();
        assertExpireTime(expectedExpire, initiateCapture);
    }

    private void assertServerVersion() {
        final TwoWayChannelMessage response = serverVersionCapture.getValue();
        final MessageType type = response.getType();
        assertEquals("Wrong type " + type, MessageType.SERVER_VERSION, type);
        final long major = response.getServerVersion().getMajor();
        assertEquals("Wrong major version", SERVER_MAJOR_VERSION, major);
    }

    private void assertExpireTime(long expectedExpire, Capture<TwoWayChannelMessage> initiateCapture) {
        final TwoWayChannelMessage response = initiateCapture.getValue();
        final MessageType type = response.getType();
        assertEquals("Wrong type " + type, MessageType.INITIATE, type);
        final long actualExpire = response.getInitiate().getExpireTimeSecs();
        assertTrue("Expire time too small " + expectedExpire + " > " + actualExpire, expectedExpire <= actualExpire);
        assertTrue("Expire time too large  " + expectedExpire + "<" + actualExpire, expectedExpire >= actualExpire);
    }

    private TwoWayChannelMessage createClientVersionMessage() {
        final Protos.ClientVersion.Builder clientVersion = Protos.ClientVersion.newBuilder().setMajor(CLIENT_MAJOR_VERSION);
        return TwoWayChannelMessage.newBuilder().setType(MessageType.CLIENT_VERSION).setClientVersion(clientVersion).build();
    }

    private TwoWayChannelMessage createClientVersionMessage(long timeWindow) {
        final Protos.ClientVersion.Builder clientVersion = Protos.ClientVersion.newBuilder().setMajor(CLIENT_MAJOR_VERSION);
        if (timeWindow > 0) clientVersion.setTimeWindowSecs(timeWindow);
        return TwoWayChannelMessage.newBuilder().setType(MessageType.CLIENT_VERSION).setClientVersion(clientVersion).build();
    }

}
