package org.bitcoinj.core;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents an "addr" message on the P2P network, which contains broadcast IP addresses of other peers. This is
 * one of the ways peers can find each other without using the DNS or IRC discovery mechanisms. However storing and
 * using addr messages is not presently implemented.
 */
public class AddressMessage extends Message {
    private static final long serialVersionUID = 8058283864924679460L;
    private static final long MAX_ADDRESSES = 1024;
    private List<PeerAddress> addresses;
    private transient long numAddresses = -1;

    /**
     * Contruct a new 'addr' message.
     * @param params NetworkParameters object.
     * @param offset The location of the first payload byte within the array.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    AddressMessage(NetworkParameters params, byte[] payload, int offset, boolean parseLazy, boolean parseRetain, int length) throws ProtocolException {
        super(params, payload, offset, parseLazy, parseRetain, length);
    }

    /**
     * Contruct a new 'addr' message.
     * @param params NetworkParameters object.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    AddressMessage(NetworkParameters params, byte[] payload, boolean parseLazy, boolean parseRetain, int length) throws ProtocolException {
        super(params, payload, 0, parseLazy, parseRetain, length);
    }

    AddressMessage(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset, false, false, UNKNOWN_LENGTH);
    }

    AddressMessage(NetworkParameters params, byte[] payload) throws ProtocolException {
        super(params, payload, 0, false, false, UNKNOWN_LENGTH);
    }

    @Override
    protected void parseLite() throws ProtocolException {
    }

    @Override
    void parse() throws ProtocolException {
        numAddresses = readVarInt();
        // Guard against ultra large messages that will crash us.
        if (numAddresses > MAX_ADDRESSES)
            throw new ProtocolException("Address message too large.");
        addresses = new ArrayList<PeerAddress>((int) numAddresses);
        for (int i = 0; i < numAddresses; i++) {
            PeerAddress addr = new PeerAddress(params, payload, cursor, protocolVersion, this, parseLazy, parseRetain);
            addresses.add(addr);
            cursor += addr.getMessageSize();
        }
        length = cursor - offset;
    }

    /* (non-Javadoc)
      * @see Message#bitcoinSerializeToStream(java.io.OutputStream)
      */
    @Override
    void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (addresses == null)
            return;
        stream.write(new VarInt(addresses.size()).encode());
        for (PeerAddress addr : addresses) {
            addr.bitcoinSerialize(stream);
        }
    }

    @Override
    public int getMessageSize() {
        if (length != UNKNOWN_LENGTH)
            return length;
        if (addresses != null) {
            length = new VarInt(addresses.size()).getSizeInBytes();
            // The 4 byte difference is the uint32 timestamp that was introduced in version 31402
            length += addresses.size() * (protocolVersion > 31402 ? PeerAddress.MESSAGE_SIZE : PeerAddress.MESSAGE_SIZE - 4);
        }
        return length;
    }

    /**
     * AddressMessage cannot cache checksum in non-retain mode due to dynamic time being used.
     */
    @Override
    void setChecksum(byte[] checksum) {
        if (parseRetain)
            super.setChecksum(checksum);
        else
            this.checksum = null;
    }

    /**
     * @return An unmodifiableList view of the backing List of addresses.  Addresses contained within the list may be safely modified.
     */
    public List<PeerAddress> getAddresses() {
        maybeParse();
        return Collections.unmodifiableList(addresses);
    }

    public void addAddress(PeerAddress address) {
        unCache();
        maybeParse();
        address.setParent(this);
        addresses.add(address);
        if (length == UNKNOWN_LENGTH)
            getMessageSize();
        else
            length += address.getMessageSize();
    }

    public void removeAddress(int index) {
        unCache();
        PeerAddress address = addresses.remove(index);
        address.setParent(null);
        if (length == UNKNOWN_LENGTH)
            getMessageSize();
        else
            length -= address.getMessageSize();
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
