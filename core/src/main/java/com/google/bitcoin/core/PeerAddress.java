/**
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.core;

import com.google.bitcoin.params.MainNetParams;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import static com.google.bitcoin.core.Utils.uint32ToByteStreamLE;
import static com.google.bitcoin.core.Utils.uint64ToByteStreamLE;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A PeerAddress holds an IP address and port number representing the network location of
 * a peer in the Bitcoin P2P network. It exists primarily for serialization purposes.
 */
public class PeerAddress extends ChildMessage {
    private static final long serialVersionUID = 7501293709324197411L;
    static final int MESSAGE_SIZE = 30;

    private InetAddress addr;
    private int port;
    private BigInteger services;
    private long time;

    /**
     * Construct a peer address from a serialized payload.
     */
    public PeerAddress(NetworkParameters params, byte[] payload, int offset, int protocolVersion) throws ProtocolException {
        super(params, payload, offset, protocolVersion);
    }

    /**
     * Construct a peer address from a serialized payload.
     * @param params NetworkParameters object.
     * @param msg Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first msg byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @throws ProtocolException
     */
    public PeerAddress(NetworkParameters params, byte[] msg, int offset, int protocolVersion, Message parent, boolean parseLazy,
                       boolean parseRetain) throws ProtocolException {
        super(params, msg, offset, protocolVersion, parent, parseLazy, parseRetain, UNKNOWN_LENGTH);
        // Message length is calculated in parseLite which is guaranteed to be called before it is ever read.
        // Even though message length is static for a PeerAddress it is safer to leave it there 
        // as it will be set regardless of which constructor was used.
    }


    /**
     * Construct a peer address from a memorized or hardcoded address.
     */
    public PeerAddress(InetAddress addr, int port, int protocolVersion) {
        this.addr = checkNotNull(addr);
        this.port = port;
        this.protocolVersion = protocolVersion;
        this.services = BigInteger.ZERO;
        length = protocolVersion > 31402 ? MESSAGE_SIZE : MESSAGE_SIZE - 4;
    }

    /**
     * Constructs a peer address from the given IP address and port. Protocol version is the default.
     */
    public PeerAddress(InetAddress addr, int port) {
        this(addr, port, NetworkParameters.PROTOCOL_VERSION);
    }

    /**
     * Constructs a peer address from the given IP address. Port and protocol version are default for the prodnet.
     */
    public PeerAddress(InetAddress addr) {
        this(addr, MainNetParams.get().getPort());
    }

    public PeerAddress(InetSocketAddress addr) {
        this(addr.getAddress(), addr.getPort());
    }

    public static PeerAddress localhost(NetworkParameters params) {
        try {
            return new PeerAddress(InetAddress.getLocalHost(), params.getPort());
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Broken system.
        }
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (protocolVersion >= 31402) {
            //TODO this appears to be dynamic because the client only ever sends out it's own address
            //so assumes itself to be up.  For a fuller implementation this needs to be dynamic only if
            //the address refers to this client.
            int secs = (int) (Utils.now().getTime() / 1000);
            uint32ToByteStreamLE(secs, stream);
        }
        uint64ToByteStreamLE(services, stream);  // nServices.
        // Java does not provide any utility to map an IPv4 address into IPv6 space, so we have to do it by hand.
        byte[] ipBytes = addr.getAddress();
        if (ipBytes.length == 4) {
            byte[] v6addr = new byte[16];
            System.arraycopy(ipBytes, 0, v6addr, 12, 4);
            v6addr[10] = (byte) 0xFF;
            v6addr[11] = (byte) 0xFF;
            ipBytes = v6addr;
        }
        stream.write(ipBytes);
        // And write out the port. Unlike the rest of the protocol, address and port is in big endian byte order.
        stream.write((byte) (0xFF & port >> 8));
        stream.write((byte) (0xFF & port));
    }

    protected void parseLite() {
        length = protocolVersion > 31402 ? MESSAGE_SIZE : MESSAGE_SIZE - 4;
    }

    @Override
    protected void parse() throws ProtocolException {
        // Format of a serialized address:
        //   uint32 timestamp
        //   uint64 services   (flags determining what the node can do)
        //   16 bytes ip address
        //   2 bytes port num
        if (protocolVersion > 31402)
            time = readUint32();
        else
            time = -1;
        services = readUint64();
        byte[] addrBytes = readBytes(16);
        try {
            addr = InetAddress.getByAddress(addrBytes);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
        port = ((0xFF & bytes[cursor++]) << 8) | (0xFF & bytes[cursor++]);
    }

    /* (non-Javadoc)
      * @see Message#getMessageSize()
      */
    @Override
    public int getMessageSize() {
        // The 4 byte difference is the uint32 timestamp that was introduced in version 31402 
        length = protocolVersion > 31402 ? MESSAGE_SIZE : MESSAGE_SIZE - 4;
        return length;
    }

    /**
     * @return the addr
     */
    public InetAddress getAddr() {
        maybeParse();
        return addr;
    }


    /**
     * @param addr the addr to set
     */
    public void setAddr(InetAddress addr) {
        unCache();
        this.addr = addr;
    }


    /**
     * @return the port
     */
    public int getPort() {
        maybeParse();
        return port;
    }


    /**
     * @param port the port to set
     */
    public void setPort(int port) {
        unCache();
        this.port = port;
    }


    /**
     * @return the services
     */
    public BigInteger getServices() {
        maybeParse();
        return services;
    }


    /**
     * @param services the services to set
     */
    public void setServices(BigInteger services) {
        unCache();
        this.services = services;
    }


    /**
     * @return the time
     */
    public long getTime() {
        maybeParse();
        return time;
    }


    /**
     * @param time the time to set
     */
    public void setTime(long time) {
        unCache();
        this.time = time;
    }


    @Override
    public String toString() {
        return "[" + addr.getHostAddress() + "]:" + port;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof PeerAddress)) return false;
        PeerAddress other = (PeerAddress) o;
        return other.addr.equals(addr) &&
                other.port == port &&
                other.services.equals(services) &&
                other.time == time;
    }

    @Override
    public int hashCode() {
        return addr.hashCode() ^ port ^ (int) time ^ services.hashCode();
    }
    
    public InetSocketAddress toSocketAddress() {
        return new InetSocketAddress(addr, port);
    }
}
