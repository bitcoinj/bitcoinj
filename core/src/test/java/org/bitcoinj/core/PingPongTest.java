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

package org.bitcoinj.core;

import org.junit.Test;

import java.nio.ByteBuffer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class PingPongTest {

    @Test
    public void pingWithNonce() {
        Ping ping = Ping.of(12345L);
        assertEquals(12345L, ping.nonce());
    }

    @Test
    public void pingRandom() {
        Ping ping1 = Ping.random();
        Ping ping2 = Ping.random();
        // Random nonces should almost certainly differ
        // (extremely small probability of collision with 64-bit random values)
        assertNotEquals(ping1.nonce(), ping2.nonce());
    }

    @Test
    public void pingMessageSize() {
        Ping ping = Ping.of(0);
        assertEquals(Long.BYTES, ping.messageSize());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void pingHasNonceAlwaysTrue() {
        assertTrue(Ping.of(0).hasNonce());
        assertTrue(Ping.random().hasNonce());
    }

    @Test
    public void pingSerializeAndDeserialize() {
        Ping original = Ping.of(0xDEADBEEFL);
        ByteBuffer buf = ByteBuffer.allocate(original.messageSize());
        original.write(buf);
        buf.rewind();

        Ping deserialized = Ping.read(buf);
        assertEquals(original.nonce(), deserialized.nonce());
    }

    @Test
    public void pingSerializeNegativeNonce() {
        Ping original = Ping.of(-1L);
        ByteBuffer buf = ByteBuffer.allocate(original.messageSize());
        original.write(buf);
        buf.rewind();

        Ping deserialized = Ping.read(buf);
        assertEquals(-1L, deserialized.nonce());
    }

    @Test
    public void pingSerializeZero() {
        Ping original = Ping.of(0);
        ByteBuffer buf = ByteBuffer.allocate(original.messageSize());
        original.write(buf);
        buf.rewind();

        Ping deserialized = Ping.read(buf);
        assertEquals(0, deserialized.nonce());
    }

    @Test
    public void pingSerializeMaxValue() {
        Ping original = Ping.of(Long.MAX_VALUE);
        ByteBuffer buf = ByteBuffer.allocate(original.messageSize());
        original.write(buf);
        buf.rewind();

        Ping deserialized = Ping.read(buf);
        assertEquals(Long.MAX_VALUE, deserialized.nonce());
    }

    @Test
    public void pongWithNonce() {
        Pong pong = Pong.of(67890L);
        assertEquals(67890L, pong.nonce());
    }

    @Test
    public void pongMessageSize() {
        Pong pong = Pong.of(0);
        assertEquals(Long.BYTES, pong.messageSize());
    }

    @Test
    public void pongSerializeAndDeserialize() {
        Pong original = Pong.of(0xCAFEBABEL);
        ByteBuffer buf = ByteBuffer.allocate(original.messageSize());
        original.write(buf);
        buf.rewind();

        Pong deserialized = Pong.read(buf);
        assertEquals(original.nonce(), deserialized.nonce());
    }

    @Test
    public void pongSerializeNegativeNonce() {
        Pong original = Pong.of(Long.MIN_VALUE);
        ByteBuffer buf = ByteBuffer.allocate(original.messageSize());
        original.write(buf);
        buf.rewind();

        Pong deserialized = Pong.read(buf);
        assertEquals(Long.MIN_VALUE, deserialized.nonce());
    }

    @Test
    public void pingPongRoundTrip() {
        Ping ping = Ping.of(42L);
        Pong pong = ping.pong();
        assertEquals(ping.nonce(), pong.nonce());
    }

    @Test
    public void pingPongRoundTripRandom() {
        Ping ping = Ping.random();
        Pong pong = ping.pong();
        assertEquals(ping.nonce(), pong.nonce());
    }

    @Test
    public void pingPongSerializeRoundTrip() {
        // Simulate full network round-trip: ping -> serialize -> deserialize -> pong -> serialize -> deserialize
        Ping originalPing = Ping.of(999999L);

        ByteBuffer pingBuf = ByteBuffer.allocate(originalPing.messageSize());
        originalPing.write(pingBuf);
        pingBuf.rewind();
        Ping receivedPing = Ping.read(pingBuf);

        Pong replyPong = receivedPing.pong();
        ByteBuffer pongBuf = ByteBuffer.allocate(replyPong.messageSize());
        replyPong.write(pongBuf);
        pongBuf.rewind();
        Pong receivedPong = Pong.read(pongBuf);

        assertEquals(originalPing.nonce(), receivedPong.nonce());
    }
}
