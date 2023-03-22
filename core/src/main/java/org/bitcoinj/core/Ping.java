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

import org.bitcoinj.base.internal.ByteUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Random;

/**
 * See <a href="https://github.com/bitcoin/bips/blob/master/bip-0031.mediawiki">BIP31</a> for details.
 * <p>
 * Instances of this class are immutable.
 */
public class Ping extends BaseMessage {
    private final long nonce;

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static Ping read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        return new Ping(ByteUtils.readInt64(payload));
    }

    /**
     * Create a ping with a nonce value.
     * Only use this if the remote node has a protocol version greater than 60000
     *
     * @param nonce nonce value
     * @return ping message
     */
    public static Ping of(long nonce) {
        return new Ping(nonce);
    }

    /**
     * Create a ping with a random nonce value.
     * Only use this if the remote node has a protocol version greater than 60000
     *
     * @return ping message
     */
    public static Ping random() {
        long nonce = new Random().nextLong();
        return new Ping(nonce);
    }

    private Ping(long nonce) {
        this.nonce = nonce;
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        ByteUtils.writeInt64LE(nonce, stream);
    }

    /** @deprecated returns true */
    @Deprecated
    public boolean hasNonce() {
        return true;
    }

    public long nonce() {
        return nonce;
    }

    /**
     * Create a {@link Pong} reply to this ping.
     *
     * @return pong message
     */
    public Pong pong() {
        return Pong.of(nonce);
    }
}
