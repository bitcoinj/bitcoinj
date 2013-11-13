package com.google.bitcoin.protocols.channels;

import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.TransactionBroadcaster;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.core.Wallet;
import org.bitcoin.paymentchannel.Protos;

import java.math.BigInteger;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static org.junit.Assert.assertEquals;

/**
 * Various mock objects and utilities for testing payment channels code.
 */
public class ChannelTestUtils {
    public static class RecordingServerConnection implements PaymentChannelServer.ServerConnection {
        public BlockingQueue<Object> q = new LinkedBlockingQueue<Object>();

        @Override
        public void sendToClient(Protos.TwoWayChannelMessage msg) {
            q.add(msg);
        }

        @Override
        public void destroyConnection(PaymentChannelCloseException.CloseReason reason) {
            q.add(reason);
        }

        @Override
        public void channelOpen(Sha256Hash contractHash) {
            q.add(contractHash);
        }

        @Override
        public void paymentIncrease(BigInteger by, BigInteger to) {
            q.add(to);
        }

        public Protos.TwoWayChannelMessage getNextMsg() throws InterruptedException {
            return (Protos.TwoWayChannelMessage) q.take();
        }

        public Protos.TwoWayChannelMessage checkNextMsg(Protos.TwoWayChannelMessage.MessageType expectedType) throws InterruptedException {
            Protos.TwoWayChannelMessage msg = getNextMsg();
            assertEquals(expectedType, msg.getType());
            return msg;
        }

        public void checkTotalPayment(BigInteger valueSoFar) throws InterruptedException {
            BigInteger lastSeen = (BigInteger) q.take();
            assertEquals(lastSeen, valueSoFar);
        }
    }

    public static class RecordingClientConnection implements PaymentChannelClient.ClientConnection {
        public BlockingQueue<Object> q = new LinkedBlockingQueue<Object>();

        // An arbitrary sentinel object for equality testing.
        public static final Object CHANNEL_INITIATED = new Object();
        public static final Object CHANNEL_OPEN = new Object();

        @Override
        public void sendToServer(Protos.TwoWayChannelMessage msg) {
            q.add(msg);
        }

        @Override
        public void destroyConnection(PaymentChannelCloseException.CloseReason reason) {
            q.add(reason);
        }

        @Override
        public void channelOpen(boolean wasInitiated) {
            if (wasInitiated)
                q.add(CHANNEL_INITIATED);
            q.add(CHANNEL_OPEN);
        }

        public Protos.TwoWayChannelMessage getNextMsg() throws InterruptedException {
            return (Protos.TwoWayChannelMessage) q.take();
        }

        public Protos.TwoWayChannelMessage checkNextMsg(Protos.TwoWayChannelMessage.MessageType expectedType) throws InterruptedException {
            Protos.TwoWayChannelMessage msg = getNextMsg();
            assertEquals(expectedType, msg.getType());
            return msg;
        }

        public void checkOpened() throws InterruptedException {
            assertEquals(CHANNEL_OPEN, q.take());
        }

        public void checkInitiated() throws InterruptedException {
            assertEquals(CHANNEL_INITIATED, q.take());
            checkOpened();
        }
    }

    public static class RecordingPair {
        public PaymentChannelServer server;
        public RecordingServerConnection serverRecorder;
        public RecordingClientConnection clientRecorder;
    }

    public static RecordingPair makeRecorders(final Wallet serverWallet, final TransactionBroadcaster mockBroadcaster) {
        RecordingPair pair = new RecordingPair();
        pair.serverRecorder = new RecordingServerConnection();
        pair.server = new PaymentChannelServer(mockBroadcaster, serverWallet, Utils.COIN, pair.serverRecorder);
        pair.clientRecorder = new RecordingClientConnection();
        return pair;
    }
}
