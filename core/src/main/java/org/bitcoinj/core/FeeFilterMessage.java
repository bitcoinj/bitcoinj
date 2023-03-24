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
import org.bitcoinj.base.internal.ByteUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * <p>Represents an "feefilter" message on the P2P network, which instructs a peer to filter transaction invs for
 * transactions that fall below the feerate provided.</p>
 *
 * <p>See <a href="https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki">BIP133</a> for details.</p>
 *
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class FeeFilterMessage extends Message {
    private Coin feeRate;

    public FeeFilterMessage(NetworkParameters params, ByteBuffer payload, BitcoinSerializer serializer) {
        super(params, payload, serializer);
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        super.bitcoinSerializeToStream(stream);
        ByteUtils.writeInt64LE(feeRate.value, stream);
    }

    @Override
    protected void parse() throws BufferUnderflowException, ProtocolException {
        feeRate = Coin.ofSat(readInt64());
        check(feeRate.signum() >= 0, () -> new ProtocolException("fee rate out of range: " + feeRate));
    }

    public Coin getFeeRate() {
        return feeRate;
    }

    @Override
    public String toString() {
        return "feefilter: " + feeRate.toFriendlyString() + "/kB";
    }
}
