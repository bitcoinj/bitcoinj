package com.google.bitcoin.protocols.channels;

import com.google.bitcoin.core.Coin;
import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.TransactionBroadcaster;
import com.google.bitcoin.core.Wallet;

import com.google.protobuf.ByteString;
import org.bitcoin.paymentchannel.Protos;

import javax.annotation.Nullable;
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
        public ByteString paymentIncrease(Coin by, Coin to, @Nullable ByteString info) {
            q.add(new UpdatePair(to, info));
            return ByteString.copyFromUtf8(by.toPlainString());
        }

        public Protos.TwoWayChannelMessage getNextMsg() throws InterruptedException {
            return (Protos.TwoWayChannelMessage) q.take();
        }

        public Protos.TwoWayChannelMessage checkNextMsg(Protos.TwoWayChannelMessage.MessageType expectedType) throws InterruptedException {
            Protos.TwoWayChannelMessage msg = getNextMsg();
            assertEquals(expectedType, msg.getType());
            return msg;
        }

        public void checkTotalPayment(Coin valueSoFar) throws InterruptedException {
            Coin lastSeen = ((UpdatePair) q.take()).amount;
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
        pair.server = new PaymentChannelServer(mockBroadcaster, serverWallet, Coin.COIN, pair.serverRecorder);
        pair.clientRecorder = new RecordingClientConnection();
        return pair;
    }

    public static class UpdatePair {
        public Coin amount;
        public ByteString info;

        public UpdatePair(Coin amount, ByteString info) {
            this.amount = amount;
            this.info = info;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            UpdatePair that = (UpdatePair) o;

            if (amount != null ? !amount.equals(that.amount) : that.amount != null) return false;
            if (info != null ? !info.equals(that.info) : that.info != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = amount != null ? amount.hashCode() : 0;
            result = 31 * result + (info != null ? info.hashCode() : 0);
            return result;
        }

        public void assertPair(Coin amount, ByteString info) {
            assertEquals(amount, this.amount);
            assertEquals(info, this.info);
        }
    }

}
