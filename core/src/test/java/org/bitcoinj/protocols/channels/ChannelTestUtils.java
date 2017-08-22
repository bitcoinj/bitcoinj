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

package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.TransactionBroadcaster;
import org.bitcoinj.wallet.Wallet;

import com.google.common.base.Objects;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.bitcoin.paymentchannel.Protos;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static org.junit.Assert.assertEquals;

/**
 * Various mock objects and utilities for testing payment channels code.
 */
public class ChannelTestUtils {
    public static class RecordingServerConnection implements PaymentChannelServer.ServerConnection {
        public BlockingQueue<Object> q = new LinkedBlockingQueue<>();

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
        public ListenableFuture<ByteString> paymentIncrease(Coin by, Coin to, @Nullable ByteString info) {
            q.add(new UpdatePair(to, info));
            return Futures.immediateFuture(ByteString.copyFromUtf8(by.toPlainString()));
        }

        @Nullable
        @Override
        public ListenableFuture<KeyParameter> getUserKey() {
            return null;
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
        public BlockingQueue<Object> q = new LinkedBlockingQueue<>();
        static final int IGNORE_EXPIRE = -1;
        private final int maxExpireTime;

        // An arbitrary sentinel object for equality testing.
        public static final Object CHANNEL_INITIATED = new Object();
        public static final Object CHANNEL_OPEN = new Object();

        public RecordingClientConnection(int maxExpireTime) {
            this.maxExpireTime = maxExpireTime;
        }

        @Override
        public void sendToServer(Protos.TwoWayChannelMessage msg) {
            q.add(msg);
        }

        @Override
        public void destroyConnection(PaymentChannelCloseException.CloseReason reason) {
            q.add(reason);
        }

        @Override
        public boolean acceptExpireTime(long expireTime) {
            return this.maxExpireTime == IGNORE_EXPIRE || expireTime <= maxExpireTime;
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
        return makeRecorders(serverWallet, mockBroadcaster, RecordingClientConnection.IGNORE_EXPIRE);
    }
    public static RecordingPair makeRecorders(final Wallet serverWallet, final TransactionBroadcaster mockBroadcaster, int maxExpireTime) {
        RecordingPair pair = new RecordingPair();
        pair.serverRecorder = new RecordingServerConnection();
        pair.server = new PaymentChannelServer(mockBroadcaster, serverWallet, Coin.COIN, pair.serverRecorder);
        pair.clientRecorder = new RecordingClientConnection(maxExpireTime);
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
            UpdatePair other = (UpdatePair) o;
            return Objects.equal(amount, other.amount) && Objects.equal(info, other.info);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(amount, info);
        }

        public void assertPair(Coin amount, ByteString info) {
            assertEquals(amount, this.amount);
            assertEquals(info, this.info);
        }
    }

}
