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

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;

/**
 * <p>Represents an "addr" message on the P2P network, which contains broadcast IP addresses of other peers. This is
 * one of the ways peers can find each other without using the DNS or IRC discovery mechanisms. However storing and
 * using addr messages is not presently implemented.</p>
 *
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class AddressV1Message extends AddressMessage {

    /**
     * Construct a new 'addr' message.
     * @param params NetworkParameters object.
     * @param serializer the serializer to use for this block.
     * @throws ProtocolException
     */
    AddressV1Message(NetworkParameters params, ByteBuffer payload, MessageSerializer serializer) throws ProtocolException {
        super(params, payload, serializer);
    }

    AddressV1Message(NetworkParameters params, ByteBuffer payload) throws ProtocolException {
        super(params, payload, params.getDefaultSerializer());
    }

    @Override
    protected void parse() throws BufferUnderflowException, ProtocolException {
        final VarInt numAddressesVarInt = VarInt.read(payload);
        int numAddresses = numAddressesVarInt.intValue();
        // Guard against ultra large messages that will crash us.
        if (numAddresses > MAX_ADDRESSES)
            throw new ProtocolException("Address message too large.");
        addresses = new ArrayList<>(numAddresses);
        MessageSerializer serializer = this.serializer.withProtocolVersion(1);
        for (int i = 0; i < numAddresses; i++) {
            PeerAddress addr = new PeerAddress(params, payload, this, serializer);
            addresses.add(addr);
        }
    }

    public void addAddress(PeerAddress address) {
        int protocolVersion = address.serializer.getProtocolVersion();
        if (protocolVersion != 1)
            throw new IllegalStateException("invalid protocolVersion: " + protocolVersion);

        unCache();
        address.setParent(this);
        addresses.add(address);
    }

    @Override
    public String toString() {
        return "addr: " + InternalUtils.SPACE_JOINER.join(addresses);
    }
}
