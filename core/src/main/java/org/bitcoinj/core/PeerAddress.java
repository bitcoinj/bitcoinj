/*
 * Copyright 2011 Google Inc.
 * Copyright 2015 Andreas Schildbach
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

import org.bitcoinj.params.MainNetParams;
import com.google.common.base.Objects;
import com.google.common.net.InetAddresses;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import static org.bitcoinj.core.Utils.uint32ToByteStreamLE;
import static org.bitcoinj.core.Utils.uint64ToByteStreamLE;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>A PeerAddress holds an IP address and port number representing the network location of
 * a peer in the Bitcoin P2P network. It exists primarily for serialization purposes.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class PeerAddress extends ChildMessage {

    static final int MESSAGE_SIZE = 30;

    private InetAddress addr;
    private String hostname; // Used for .onion addresses
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
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     * @param serializer the serializer to use for this message.
     * @throws ProtocolException
     */
    public PeerAddress(NetworkParameters params, byte[] payload, int offset, int protocolVersion, Message parent, MessageSerializer serializer) throws ProtocolException {
        super(params, payload, offset, protocolVersion, parent, serializer, UNKNOWN_LENGTH);
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
     * Constructs a peer address from the given IP address and port. Protocol version is the default
     * for Bitcoin.
     */
    public PeerAddress(InetAddress addr, int port) {
        this(addr, port, NetworkParameters.ProtocolVersion.CURRENT.getBitcoinProtocolVersion());
    }

    /**
     * Constructs a peer address from the given IP address and port.
     */
    public PeerAddress(NetworkParameters params, InetAddress addr, int port) {
        this(addr, port, params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT));
    }

    /**
     * Constructs a peer address from the given IP address. Port and version number
     * are default for Bitcoin mainnet.
     */
    public PeerAddress(InetAddress addr) {
        this(addr, MainNetParams.get().getPort());
    }

    /**
     * Constructs a peer address from the given IP address. Port is default for
     * Bitcoin mainnet, version number is default for the given parameters.
     */
    public PeerAddress(NetworkParameters params, InetAddress addr) {
        this(params, addr, params.getPort());
    }

    /**
     * Constructs a peer address from an {@link InetSocketAddress}. An InetSocketAddress can take in as parameters an
     * InetAddress or a String hostname. If you want to connect to a .onion, set the hostname to the .onion address.
     * Protocol version is the default.  Protocol version is the default
     * for Bitcoin.
     */
    public PeerAddress(InetSocketAddress addr) {
        this(addr.getAddress(), addr.getPort(), NetworkParameters.ProtocolVersion.CURRENT.getBitcoinProtocolVersion());
    }

    /**
     * Constructs a peer address from an {@link InetSocketAddress}. An InetSocketAddress can take in as parameters an
     * InetAddress or a String hostname. If you want to connect to a .onion, set the hostname to the .onion address.
     */
    public PeerAddress(NetworkParameters params, InetSocketAddress addr) {
        this(params, addr.getAddress(), addr.getPort());
    }

    /**
     * Constructs a peer address from a stringified hostname+port. Use this if you want to connect to a Tor .onion address.
     * Protocol version is the default for Bitcoin.
     */
    public PeerAddress(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
        this.protocolVersion = NetworkParameters.ProtocolVersion.CURRENT.getBitcoinProtocolVersion();
        this.services = BigInteger.ZERO;
    }

    /**
     * Constructs a peer address from a stringified hostname+port. Use this if you want to connect to a Tor .onion address.
     */
    public PeerAddress(NetworkParameters params, String hostname, int port) {
        super(params);
        this.hostname = hostname;
        this.port = port;
        this.protocolVersion = params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT);
        this.services = BigInteger.ZERO;
    }

    public static PeerAddress localhost(NetworkParameters params) {
        return new PeerAddress(params, InetAddresses.forString("127.0.0.1"), params.getPort());
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (protocolVersion >= 31402) {
            //TODO this appears to be dynamic because the client only ever sends out it's own address
            //so assumes itself to be up.  For a fuller implementation this needs to be dynamic only if
            //the address refers to this client.
            int secs = (int) (Utils.currentTimeSeconds());
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
        port = ((0xFF & payload[cursor++]) << 8) | (0xFF & payload[cursor++]);
        // The 4 byte difference is the uint32 timestamp that was introduced in version 31402 
        length = protocolVersion > 31402 ? MESSAGE_SIZE : MESSAGE_SIZE - 4;
    }

    public String getHostname() {
        return hostname;
    }

    public InetAddress getAddr() {
        return addr;
    }

    public InetSocketAddress getSocketAddress() {
        return new InetSocketAddress(getAddr(), getPort());
    }

    public void setAddr(InetAddress addr) {
        unCache();
        this.addr = addr;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        unCache();
        this.port = port;
    }

    public BigInteger getServices() {
        return services;
    }

    public void setServices(BigInteger services) {
        unCache();
        this.services = services;
    }

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        unCache();
        this.time = time;
    }

    @Override
    public String toString() {
        if (hostname != null) {
            return "[" + hostname + "]:" + port;
        }
        return "[" + addr.getHostAddress() + "]:" + port;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PeerAddress other = (PeerAddress) o;
        return other.addr.equals(addr) && other.port == port && other.time == time && other.services.equals(services);
        //TODO: including services and time could cause same peer to be added multiple times in collections
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(addr, port, time, services);
    }
    
    public InetSocketAddress toSocketAddress() {
        // Reconstruct the InetSocketAddress properly
        if (hostname != null) {
            return InetSocketAddress.createUnresolved(hostname, port);
        } else {
            return new InetSocketAddress(addr, port);
        }
    }
}
