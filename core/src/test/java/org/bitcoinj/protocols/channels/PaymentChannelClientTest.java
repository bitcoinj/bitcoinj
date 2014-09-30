package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.*;
import org.bitcoin.paymentchannel.Protos;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;

import static org.bitcoin.paymentchannel.Protos.TwoWayChannelMessage;
import static org.bitcoin.paymentchannel.Protos.TwoWayChannelMessage.MessageType.*;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;

public class PaymentChannelClientTest {

    private static final int CLIENT_MAJOR_VERSION = 1;
    private Wallet wallet;
    private ECKey ecKey;
    private Sha256Hash serverHash;
    private IPaymentChannelClient.ClientConnection connection;
    public Coin maxValue;
    public Capture<TwoWayChannelMessage> clientVersionCapture;
    public int defaultTimeWindow = 86340;

    @Before
    public void before() {
        wallet = createMock(Wallet.class);
        ecKey = createMock(ECKey.class);
        maxValue = Coin.COIN;
        serverHash = Sha256Hash.create("serverId".getBytes());
        connection = createMock(IPaymentChannelClient.ClientConnection.class);
        clientVersionCapture = new Capture<TwoWayChannelMessage>();
    }

    @Test
    public void shouldSendClientVersionOnChannelOpen() throws Exception {
        PaymentChannelClient dut = new PaymentChannelClient(wallet, ecKey, maxValue, serverHash, connection);
        connection.sendToServer(capture(clientVersionCapture));
        EasyMock.expect(wallet.getExtensions()).andReturn(new HashMap<String, WalletExtension>());
        replay(connection, wallet);
        dut.connectionOpen();
        assertClientVersion(defaultTimeWindow);
    }
    @Test
    public void shouldSendTimeWindowInClientVersion() throws Exception {
        long timeWindow = 4000;
        PaymentChannelClient dut = new PaymentChannelClient(wallet, ecKey, maxValue, serverHash, timeWindow, connection);
        connection.sendToServer(capture(clientVersionCapture));
        EasyMock.expect(wallet.getExtensions()).andReturn(new HashMap<String, WalletExtension>());
        replay(connection, wallet);
        dut.connectionOpen();
        assertClientVersion(4000);
    }

    private void assertClientVersion(long expectedTimeWindow) {
        final TwoWayChannelMessage response = clientVersionCapture.getValue();
        final TwoWayChannelMessage.MessageType type = response.getType();
        assertEquals("Wrong type " + type, CLIENT_VERSION, type);
        final Protos.ClientVersion clientVersion = response.getClientVersion();
        final int major = clientVersion.getMajor();
        assertEquals("Wrong major version " + major, CLIENT_MAJOR_VERSION, major);
        final long actualTimeWindow = clientVersion.getTimeWindowSecs();
        assertEquals("Wrong timeWindow " + actualTimeWindow, expectedTimeWindow, actualTimeWindow );
    }
}
