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

import org.bitcoinj.base.Coin;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * Represents a "feefilter" message on the P2P network, which instructs a peer to filter transaction invs for
 * transactions that fall below the feerate provided.
 * <p>
 * See <a href="https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki">BIP133</a> for details.
 * <p>
 * Instances of this class are immutable.
 */
public class FeeFilterMessage extends BaseMessage {
    private final Coin feeRate;

    /**
     * Create a fee filter message with a given fee rate.
     *
     * @param feeRate fee rate
     * @return fee filter message
     */
    public static FeeFilterMessage of(Coin feeRate) {
        return new FeeFilterMessage(feeRate);
    }

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static FeeFilterMessage read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        Coin feeRate = Coin.read(payload);
        check(feeRate.signum() >= 0, () -> new ProtocolException("fee rate out of range: " + feeRate));
        return new FeeFilterMessage(feeRate);
    }

    private FeeFilterMessage(Coin feeRate) {
        this.feeRate = feeRate;
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(feeRate.serialize());
    }

    /**
     * Gets the fee rate.
     *
     * @return fee rate
     */
    public Coin feeRate() {
        return feeRate;
    }

    /**
     * @deprecated use {@link #feeRate()}
     */
    @Deprecated
    public Coin getFeeRate() {
        return feeRate();
    }

    @Override
    public String toString() {
        return "feefilter: " + feeRate.toFriendlyString() + "/kB";
    }
}
