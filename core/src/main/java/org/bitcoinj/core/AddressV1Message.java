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

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * Represents an "addr" message on the P2P network, which contains broadcast IP addresses of other peers. This is
 * one of the ways peers can find each other without using the {@link PeerDiscovery} mechanism.
 * <p>
 * Instances of this class are not safe for use by multiple threads.
 */
public class AddressV1Message extends AddressMessage {
    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static AddressV1Message read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        return new AddressV1Message(readAddresses(payload, 1));
    }

    private AddressV1Message(List<PeerAddress> addresses) {
        super(addresses);
    }

    public void addAddress(PeerAddress address) {
        addresses.add(address);
    }

    @Override
    public int messageSize() {
        if (addresses == null)
            return 0;
        return VarInt.sizeOf(addresses.size()) +
                addresses.stream()
                        .mapToInt(addr -> addr.getMessageSize(1))
                        .sum();
    }

    @Override
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        if (addresses != null) {
            VarInt.of(addresses.size()).write(buf);
            for (PeerAddress addr : addresses) {
                addr.write(buf, 1);
            }
        }
        return buf;
    }

    @Override
    public String toString() {
        return "addr: " + InternalUtils.SPACE_JOINER.join(addresses);
    }
}
