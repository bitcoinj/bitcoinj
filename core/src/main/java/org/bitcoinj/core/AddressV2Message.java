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

import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.InternalUtils;
import org.bitcoinj.net.discovery.PeerDiscovery;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * Represents an "addrv2" message on the P2P network, which contains broadcast addresses of other peers. This is
 * one of the ways peers can find each other without using the {@link PeerDiscovery} mechanism.
 * <p>
 * See <a href="https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki">BIP155</a> for details.
 * <p>
 * Instances of this class are not safe for use by multiple threads.
 */
public class AddressV2Message extends AddressMessage {
    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static AddressV2Message read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        return new AddressV2Message(readAddresses(payload, 2));
    }

    private AddressV2Message(List<PeerAddress> addresses) {
        super(addresses);
    }

    public void addAddress(PeerAddress address) {
        addresses.add(address);
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (addresses == null)
            return;
        stream.write(VarInt.of(addresses.size()).serialize());
        for (PeerAddress addr : addresses) {
            stream.write(addr.serialize(2));
        }
    }

    @Override
    public String toString() {
        return "addrv2: " + InternalUtils.SPACE_JOINER.join(addresses);
    }
}
