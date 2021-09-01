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

import com.google.common.io.BaseEncoding;
import org.bouncycastle.jcajce.provider.digest.SHA3;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * <p>A PeerAddress holds an IP address and port number representing the network location of
 * a peer in the Bitcoin P2P network. It exists primarily for serialization purposes.</p>
 *
 * <p>This class abuses the protocol version contained in its serializer. It can only contain 0 (format within
 * {@link VersionMessage}), 1 ({@link AddressV1Message}) or 2 ({@link AddressV2Message}).</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class PeerAddress extends ChildMessage {
    private InetAddress addr;
    private String hostname; // Used for .onion addresses
    private int port;
    private BigInteger services;
    private long time;

    private static final BaseEncoding BASE32 = BaseEncoding.base32().lowerCase();
    private static final byte[] ONIONCAT_PREFIX = Utils.HEX.decode("fd87d87eeb43");

    /**
     * Construct a peer address from a serialized payload.
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param serializer the serializer to use for this message.
     * @throws ProtocolException
     */
    public PeerAddress(NetworkParameters params, byte[] payload, int offset, Message parent, MessageSerializer serializer) throws ProtocolException {
        super(params, payload, offset, parent, serializer, UNKNOWN_LENGTH);
    }

    /**
     * Construct a peer address from a memorized or hardcoded address.
     */
    public PeerAddress(NetworkParameters params, InetAddress addr, int port, BigInteger services, MessageSerializer serializer) {
        super(params);
        this.addr = checkNotNull(addr);
        this.port = port;
        setSerializer(serializer);
        this.services = services;
        this.time = Utils.currentTimeSeconds();
    }

    /**
     * Constructs a peer address from the given IP address, port and services. Version number is default for the given parameters.
     */
    public PeerAddress(NetworkParameters params, InetAddress addr, int port, BigInteger services) {
        this(params, addr, port, services, params.getDefaultSerializer().withProtocolVersion(0));
    }

    /**
     * Constructs a peer address from the given IP address and port. Version number is default for the given parameters.
     */
    public PeerAddress(NetworkParameters params, InetAddress addr, int port) {
        this(params, addr, port, BigInteger.ZERO);
    }

    /**
     * Constructs a peer address from the given IP address. Port and version number are default for the given
     * parameters.
     */
    public PeerAddress(NetworkParameters params, InetAddress addr) {
        this(params, addr, params.getPort());
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
     */
    public PeerAddress(NetworkParameters params, String hostname, int port) {
        super(params);
        this.hostname = hostname;
        this.port = port;
        this.services = BigInteger.ZERO;
        this.time = Utils.currentTimeSeconds();
    }

    public static PeerAddress localhost(NetworkParameters params) {
        return new PeerAddress(params, InetAddress.getLoopbackAddress(), params.getPort());
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        int protocolVersion = serializer.getProtocolVersion();
        if (protocolVersion < 0 || protocolVersion > 2)
            throw new IllegalStateException("invalid protocolVersion: " + protocolVersion);

        if (protocolVersion >= 1) {
            Utils.uint32ToByteStreamLE(time, stream);
        }
        if (protocolVersion == 2) {
            stream.write(new VarInt(services.longValue()).encode());
            if (addr != null) {
                if (addr instanceof Inet4Address) {
                    stream.write(0x01);
                    stream.write(new VarInt(4).encode());
                    stream.write(addr.getAddress());
                } else if (addr instanceof Inet6Address) {
                    stream.write(0x02);
                    stream.write(new VarInt(16).encode());
                    stream.write(addr.getAddress());
                } else {
                    throw new IllegalStateException();
                }
            } else if (addr == null && hostname != null && hostname.toLowerCase(Locale.ROOT).endsWith(".onion")) {
                byte[] onionAddress = BASE32.decode(hostname.substring(0, hostname.length() - 6));
                if (onionAddress.length == 10) {
                    // TORv2
                    stream.write(0x03);
                    stream.write(new VarInt(10).encode());
                    stream.write(onionAddress);
                } else if (onionAddress.length == 32 + 2 + 1) {
                    // TORv3
                    stream.write(0x04);
                    stream.write(new VarInt(32).encode());
                    byte[] pubkey = Arrays.copyOfRange(onionAddress, 0, 32);
                    byte[] checksum = Arrays.copyOfRange(onionAddress, 32, 34);
                    byte torVersion = onionAddress[34];
                    if (torVersion != 0x03)
                        throw new IllegalStateException("version");
                    if (!Arrays.equals(checksum, onionChecksum(pubkey, torVersion)))
                        throw new IllegalStateException("checksum");
                    stream.write(pubkey);
                } else {
                    throw new IllegalStateException();
                }
            } else {
                throw new IllegalStateException();
            }
        } else {
            Utils.uint64ToByteStreamLE(services, stream);  // nServices.
            if (addr != null) {
                // Java does not provide any utility to map an IPv4 address into IPv6 space, so we have to do it by
                // hand.
                byte[] ipBytes = addr.getAddress();
                if (ipBytes.length == 4) {
                    byte[] v6addr = new byte[16];
                    System.arraycopy(ipBytes, 0, v6addr, 12, 4);
                    v6addr[10] = (byte) 0xFF;
                    v6addr[11] = (byte) 0xFF;
                    ipBytes = v6addr;
                }
                stream.write(ipBytes);
            } else if (hostname != null && hostname.toLowerCase(Locale.ROOT).endsWith(".onion")) {
                byte[] onionAddress = BASE32.decode(hostname.substring(0, hostname.length() - 6));
                if (onionAddress.length == 10) {
                    // TORv2
                    stream.write(ONIONCAT_PREFIX);
                    stream.write(onionAddress);
                } else {
                    throw new IllegalStateException();
                }
            } else {
                throw new IllegalStateException();
            }
        }
        // And write out the port. Unlike the rest of the protocol, address and port is in big endian byte order.
        Utils.uint16ToByteStreamBE(port, stream);
    }

    @Override
    protected void parse() throws ProtocolException {
        int protocolVersion = serializer.getProtocolVersion();
        if (protocolVersion < 0 || protocolVersion > 2)
            throw new IllegalStateException("invalid protocolVersion: " + protocolVersion);

        length = 0;
        if (protocolVersion >= 1) {
            time = readUint32();
            length += 4;
        } else {
            time = -1;
        }
        if (protocolVersion == 2) {
            VarInt servicesVarInt = readVarInt();
            length += servicesVarInt.getSizeInBytes();
            services = BigInteger.valueOf(servicesVarInt.longValue());
            int networkId = readByte();
            length += 1;
            byte[] addrBytes = readByteArray();
            int addrLen = addrBytes.length;
            length += VarInt.sizeOf(addrLen) + addrLen;
            if (networkId == 0x01) {
                // IPv4
                if (addrLen != 4)
                    throw new ProtocolException("invalid length of IPv4 address: " + addrLen);
                addr = getByAddress(addrBytes);
                hostname = null;
            } else if (networkId == 0x02) {
                // IPv6
                if (addrLen != 16)
                    throw new ProtocolException("invalid length of IPv6 address: " + addrLen);
                addr = getByAddress(addrBytes);
                hostname = null;
            } else if (networkId == 0x03) {
                // TORv2
                if (addrLen != 10)
                    throw new ProtocolException("invalid length of TORv2 address: " + addrLen);
                hostname = BASE32.encode(addrBytes) + ".onion";
                addr = null;
            } else if (networkId == 0x04) {
                // TORv3
                if (addrLen != 32)
                    throw new ProtocolException("invalid length of TORv3 address: " + addrLen);
                byte torVersion = 0x03;
                byte[] onionAddress = new byte[35];
                System.arraycopy(addrBytes, 0, onionAddress, 0, 32);
                System.arraycopy(onionChecksum(addrBytes, torVersion), 0, onionAddress, 32, 2);
                onionAddress[34] = torVersion;
                hostname = BASE32.encode(onionAddress) + ".onion";
                addr = null;
            } else {
                // ignore unknown network IDs
                addr = null;
                hostname = null;
            }
        } else {
            services = readUint64();
            length += 8;
            byte[] addrBytes = readBytes(16);
            length += 16;
            if (Arrays.equals(ONIONCAT_PREFIX, Arrays.copyOf(addrBytes, 6))) {
                byte[] onionAddress = Arrays.copyOfRange(addrBytes, 6, 16);
                hostname = BASE32.encode(onionAddress) + ".onion";
            } else {
                addr = getByAddress(addrBytes);
                hostname = null;
            }
        }
        port = Utils.readUint16BE(payload, cursor);
        cursor += 2;
        length += 2;
    }

    private static InetAddress getByAddress(byte[] addrBytes) {
        try {
            return InetAddress.getByAddress(addrBytes);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    private byte[] onionChecksum(byte[] pubkey, byte version) {
        if (pubkey.length != 32)
            throw new IllegalArgumentException();
        SHA3.Digest256 digest256 = new SHA3.Digest256();
        digest256.update(".onion checksum".getBytes(StandardCharsets.US_ASCII));
        digest256.update(pubkey);
        digest256.update(version);
        return Arrays.copyOf(digest256.digest(), 2);
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

    public int getPort() {
        return port;
    }

    public BigInteger getServices() {
        return services;
    }

    public long getTime() {
        return time;
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
        return other.addr.equals(addr) && other.port == port && other.services.equals(services);
    }

    @Override
    public int hashCode() {
        return Objects.hash(addr, port, services);
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
