/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (addresses == null)
            return;
        stream.write(VarInt.of(addresses.size()).serialize());
        for (PeerAddress addr : addresses) {
            stream.write(addr.serialize(1));
        }
    }

    @Override
    public String toString() {
        return "addr: " + InternalUtils.SPACE_JOINER.join(addresses);
    }
}
