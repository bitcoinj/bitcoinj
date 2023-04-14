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
import org.bitcoinj.net.discovery.PeerDiscovery;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * Abstract superclass for address messages on the P2P network, which contain network addresses of other peers. This is
 * one of the ways peers can find each other without using the {@link PeerDiscovery} mechanism.
 */
public abstract class AddressMessage extends BaseMessage {

    protected static final long MAX_ADDRESSES = 1000;
    protected List<PeerAddress> addresses;

    protected static List<PeerAddress> readAddresses(ByteBuffer payload, int protocolVariant) throws BufferUnderflowException, ProtocolException {
        VarInt numAddressesVarInt = VarInt.read(payload);
        check(numAddressesVarInt.fitsInt(), BufferUnderflowException::new);
        int numAddresses = numAddressesVarInt.intValue();
        // Guard against ultra large messages that will crash us.
        if (numAddresses > MAX_ADDRESSES)
            throw new ProtocolException("Address message too large.");
        List<PeerAddress> addresses = new ArrayList<>(numAddresses);
        for (int i = 0; i < numAddresses; i++) {
            addresses.add(PeerAddress.read(payload, protocolVariant));
        }
        return addresses;
    }

    protected AddressMessage(List<PeerAddress> addresses) {
        this.addresses = addresses;
    }

    public abstract void addAddress(PeerAddress address);

    public void removeAddress(int index) {
        PeerAddress address = addresses.remove(index);
    }

    /**
     * @return An unmodifiableList view of the backing List of addresses. Addresses contained within the list may be
     * safely modified.
     */
    public List<PeerAddress> getAddresses() {
        return Collections.unmodifiableList(addresses);
    }
}
