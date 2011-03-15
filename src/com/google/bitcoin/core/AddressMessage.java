package com.google.bitcoin.core;

import java.util.ArrayList;
import java.util.List;

public class AddressMessage extends Message {
    private static final long serialVersionUID = 8058283864924679460L;
    private static final long MAX_ADDRESSES = 1024;
    List<PeerAddress> addresses;

    AddressMessage(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
    }

    AddressMessage(NetworkParameters params, byte[] payload) throws ProtocolException {
        super(params, payload, 0);
    }

    @Override
    void parse() throws ProtocolException {
        long numAddresses = readVarInt();
        // Guard against ultra large messages that will crash us.
        if (numAddresses > MAX_ADDRESSES)
            throw new ProtocolException("Address message too large.");
        addresses = new ArrayList<PeerAddress>((int)numAddresses);
        for (int i = 0; i < numAddresses; i++) {
            PeerAddress addr = new PeerAddress(params, bytes, cursor, protocolVersion);
            addresses.add(addr);
            cursor += addr.getMessageSize();
        }
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("addr: ");
        for (PeerAddress a : addresses) {
            builder.append(a.toString());
            builder.append(" ");
        }
        return builder.toString();
    }
}
