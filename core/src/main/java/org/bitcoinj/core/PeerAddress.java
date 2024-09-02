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

import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.Buffers;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.internal.TorUtils;

import javax.annotation.Nullable;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * A PeerAddress holds an IP address and port number representing the network location of
 * a peer in the Bitcoin P2P network. It exists primarily for serialization purposes.
 * <p>
 * Instances of this class are not safe for use by multiple threads.
 */
public class PeerAddress {
    @Nullable
    private final InetAddress addr;   // Used for IPV4, IPV6, null otherwise
    @Nullable
    private final String hostname;    // Used for (.onion addresses) TORV2, TORV3, null otherwise
    private final int port;
    private final Services services;
    private final Instant time;

    private static final byte[] ONIONCAT_PREFIX = ByteUtils.parseHex("fd87d87eeb43");

    // BIP-155 reserved network IDs, see: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
    private enum NetworkId {
        IPV4(1),
        IPV6(2),
        TORV2(3),
        TORV3(4),
        I2P(5),
        CJDNS(6);

        final int value;

        NetworkId(int value) {
            this.value = value;
        }

        static Optional<NetworkId> of(int value) {
            return Stream.of(values())
                .filter(id -> id.value == value)
                .findFirst();
        }
    }

    /**
     * Constructs a simple peer address from the given IP address and port, but without services. The time is set to
     * current time.
     *
     * @param addr ip address of peer
     * @param port port the peer is listening on
     * @return simple peer address
     */
    public static PeerAddress simple(InetAddress addr, int port) {
        return new PeerAddress(
                Objects.requireNonNull(addr),
                null,
                port,
                Services.none(),
                TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS));
    }

    /**
     * Constructs a simple peer address from the given socket address, but without services. The time is set to
     * current time.
     *
     * @param addr ip address and port of peer
     * @return simple peer address
     */
    public static PeerAddress simple(InetSocketAddress addr) {
        return new PeerAddress(
                addr.getAddress(),
                null,
                addr.getPort(),
                Services.none(),
                TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS));
    }

    /**
     * Constructs a peer address from the given IP address, port, services and time. Such addresses are used for
     * `addr` and `addrv2` messages of types IPv4 and IPv6.
     *
     * @param addr     ip address of the peer
     * @param port     port the peer is listening on
     * @param services node services the peer is providing
     * @param time     last-seen time of the peer
     */
    public static PeerAddress inet(InetAddress addr, int port, Services services, Instant time) {
        return new PeerAddress(
                Objects.requireNonNull(addr),
                null,
                port,
                Objects.requireNonNull(services),
                Objects.requireNonNull(time));
    }

    /**
     * Constructs a peer address from the given IP address, port, services and time. Such addresses are used for
     * `addr` and `addrv2` messages of types IPv4 and IPv6.
     *
     * @param addr     ip address and port of the peer
     * @param services node services the peer is providing
     * @param time     last-seen time of the peer
     */
    public static PeerAddress inet(InetSocketAddress addr, Services services, Instant time) {
        return new PeerAddress(
                addr.getAddress(),
                null,
                addr.getPort(),
                Objects.requireNonNull(services),
                Objects.requireNonNull(time));
    }

    /**
     * Deserialize this peer address from a given payload, using a given protocol variant. The variant can be
     * 1 ({@link AddressV1Message}) or 2 ({@link AddressV2Message}).
     *
     * @param payload         payload to deserialize from
     * @param protocolVariant variant of protocol to use for parsing
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static PeerAddress read(ByteBuffer payload, int protocolVariant) throws BufferUnderflowException, ProtocolException {
        if (protocolVariant < 0 || protocolVariant > 2)
            throw new IllegalStateException("invalid protocolVariant: " + protocolVariant);

        Instant time = Instant.ofEpochSecond(ByteUtils.readUint32(payload));
        Services services;
        InetAddress addr = null;
        String hostname = null;
        if (protocolVariant == 2) {
            services = Services.of(VarInt.read(payload).longValue());
            int networkId = payload.get();
            byte[] addrBytes = Buffers.readLengthPrefixedBytes(payload);
            int addrLen = addrBytes.length;
            Optional<NetworkId> id = NetworkId.of(networkId);
            if (id.isPresent()) {
                switch(id.get()) {
                    case IPV4:
                        if (addrLen != 4)
                            throw new ProtocolException("invalid length of IPv4 address: " + addrLen);
                        addr = getByAddress(addrBytes);
                        hostname = null;
                        break;
                    case IPV6:
                        if (addrLen != 16)
                            throw new ProtocolException("invalid length of IPv6 address: " + addrLen);
                        addr = getByAddress(addrBytes);
                        hostname = null;
                        break;
                    case TORV2:
                        if (addrLen != 10)
                            throw new ProtocolException("invalid length of TORv2 address: " + addrLen);
                        hostname = TorUtils.encodeOnionUrlV2(addrBytes);
                        addr = null;
                        break;
                    case TORV3:
                        if (addrLen != 32)
                            throw new ProtocolException("invalid length of TORv3 address: " + addrLen);
                        hostname = TorUtils.encodeOnionUrlV3(addrBytes);
                        addr = null;
                        break;
                    case I2P:
                    case CJDNS:
                        // ignore unimplemented network IDs for now
                        addr = null;
                        hostname = null;
                        break;
                }
            } else {
                // ignore unknown network IDs
                addr = null;
                hostname = null;
            }
        } else {
            services = Services.read(payload);
            byte[] addrBytes = Buffers.readBytes(payload, 16);
            if (Arrays.equals(ONIONCAT_PREFIX, Arrays.copyOf(addrBytes, 6))) {
                byte[] onionAddress = Arrays.copyOfRange(addrBytes, 6, 16);
                hostname = TorUtils.encodeOnionUrlV2(onionAddress);
            } else {
                addr = getByAddress(addrBytes);
                hostname = null;
            }
        }
        int port = ByteUtils.readUint16BE(payload);
        return new PeerAddress(addr, hostname, port, services, time);
    }

    private PeerAddress(InetAddress addr, String hostname, int port, Services services, Instant time) {
        this.addr = addr;
        this.hostname = hostname;
        this.port = port;
        this.services = services;
        this.time = time;
    }

    public static PeerAddress localhost(NetworkParameters params) {
        return PeerAddress.simple(InetAddress.getLoopbackAddress(), params.getPort());
    }

    /**
     * Write this peer address into the given buffer, using a given protocol variant. The variant can be
     * 1 ({@link AddressV1Message}) or 2 ({@link AddressV2Message})..
     *
     * @param buf             buffer to write into
     * @param protocolVariant variant of protocol used
     * @return the buffer
     * @throws BufferOverflowException if the peer addressdoesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf, int protocolVariant) throws BufferOverflowException {
        if (protocolVariant < 1 || protocolVariant > 2)
            throw new IllegalStateException("invalid protocolVariant: " + protocolVariant);

        ByteUtils.writeInt32LE(time.getEpochSecond(), buf);
        if (protocolVariant == 2) {
            VarInt.of(services.bits()).write(buf);
            if (addr != null) {
                if (addr instanceof Inet4Address) {
                    buf.put((byte) 0x01);
                    VarInt.of(4).write(buf);
                    buf.put(addr.getAddress());
                } else if (addr instanceof Inet6Address) {
                    buf.put((byte) 0x02);
                    VarInt.of(16).write(buf);
                    buf.put(addr.getAddress());
                } else {
                    throw new IllegalStateException();
                }
            } else if (addr == null && hostname != null && hostname.toLowerCase(Locale.ROOT).endsWith(".onion")) {
                byte[] onionAddress = TorUtils.decodeOnionUrl(hostname);
                if (onionAddress.length == 10) {
                    // TORv2
                    buf.put((byte) 0x03);
                    VarInt.of(10).write(buf);
                    buf.put(onionAddress);
                } else if (onionAddress.length == 32) {
                    // TORv3
                    buf.put((byte) 0x04);
                    VarInt.of(32).write(buf);
                    buf.put(onionAddress);
                } else {
                    throw new IllegalStateException();
                }
            } else {
                throw new IllegalStateException();
            }
        } else {
            services.write(buf);
            if (addr != null) {
                // Java does not provide any utility to map an IPv4 address into IPv6 space, so we have to do it by
                // hand.
                byte[] ipBytes = addr.getAddress();
                buf.put(mapIntoIPv6(ipBytes));
            } else if (hostname != null && hostname.toLowerCase(Locale.ROOT).endsWith(".onion")) {
                byte[] onionAddress = TorUtils.decodeOnionUrl(hostname);
                if (onionAddress.length == 10) {
                    // TORv2
                    buf.put(ONIONCAT_PREFIX);
                    buf.put(onionAddress);
                } else {
                    throw new IllegalStateException();
                }
            } else {
                throw new IllegalStateException();
            }
        }
        // And write out the port. Unlike the rest of the protocol, address and port is in big endian byte order.
        ByteUtils.writeInt16BE(port, buf);
        return buf;
    }

    /**
     * Allocates a byte array and writes this peer address into it, using a given protocol variant. The variant can be
     * 1 ({@link AddressV1Message}) or 2 ({@link AddressV2Message}).
     *
     * @param protocolVariant variant of protocol used
     * @return byte array containing the peer address
     */
    public byte[] serialize(int protocolVariant) {
        return write(ByteBuffer.allocate(getMessageSize(protocolVariant)), protocolVariant).array();
    }

    /**
     * Return the size of the serialized message, using a given protocol variant. The variant can be
     * 1 ({@link AddressV1Message}) or 2 ({@link AddressV2Message}).. Note that if the message was deserialized from
     * a payload, this size can differ from the size of the original payload.
     *
     * @param protocolVariant variant of protocol used
     * @return size of the serialized message in bytes
     */
    public int getMessageSize(int protocolVariant) {
        if (protocolVariant < 1 || protocolVariant > 2)
            throw new IllegalStateException("invalid protocolVariant: " + protocolVariant);
        int size = 0;
        size += 4; // time
        if (protocolVariant == 2) {
            size += VarInt.sizeOf(services.bits());
            size += 1; // network id
            if (addr != null) {
                if (addr instanceof Inet4Address) {
                    size += VarInt.sizeOf(4) + 4;
                } else if (addr instanceof Inet6Address) {
                    size += VarInt.sizeOf(16) + 16;
                } else {
                    throw new IllegalStateException();
                }
            } else if (addr == null && hostname != null && hostname.toLowerCase(Locale.ROOT).endsWith(".onion")) {
                byte[] onionAddress = TorUtils.decodeOnionUrl(hostname);
                if (onionAddress.length == 10 || onionAddress.length == 32) {
                    size += VarInt.sizeOf(onionAddress.length) + onionAddress.length;
                } else {
                    throw new IllegalStateException();
                }
            } else {
                throw new IllegalStateException();
            }
        } else {
            size += Services.BYTES;
            size += 16; // ip
        }
        size += 2; // port
        return size;
    }

    public static InetAddress getByAddress(byte[] addrBytes) {
        try {
            return InetAddress.getByAddress(addrBytes);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Map given IPv4 address into IPv6 space.
     *
     * @param ip IPv4 to map into IPv6 space
     * @return mapped IP
     */
    public static byte[] mapIntoIPv6(byte[] ip) {
        checkArgument(ip.length == 4 || ip.length == 16, () -> "need IPv4 or IPv6");
        if (ip.length == 16)
            return ip; // nothing to do
        byte[] ipv6 = new byte[16];
        System.arraycopy(ip, 0, ipv6, 12, 4);
        ipv6[10] = (byte) 0xFF;
        ipv6[11] = (byte) 0xFF;
        return ipv6;
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

    public Services getServices() {
        return services;
    }

    /**
     * Gets the time that the node was last seen as connected to the network.
     * @return time that the node was last seen
     */
    public Instant time() {
        return time;
    }

    @Override
    public String toString() {
        if (hostname != null) {
            return "[" + hostname + "]:" + port;
        } else if (addr != null) {
            return "[" + addr.getHostAddress() + "]:" + port;
        } else {
            return "[ PeerAddress of unsupported type ]:" + port;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PeerAddress other = (PeerAddress) o;
        // time is deliberately not included in equals
        return  Objects.equals(addr, other.addr) &&
                Objects.equals(hostname, other.hostname) &&
                port == other.port &&
                Objects.equals(services, other.services);
    }

    @Override
    public int hashCode() {
        // time is deliberately not included in hashcode
        return Objects.hash(addr, hostname, port, services);
    }
    
    public InetSocketAddress toSocketAddress() {
        // Reconstruct the InetSocketAddress properly
        if (hostname != null) {
            return InetSocketAddress.createUnresolved(hostname, port);
        } else {
            // A null addr will create a wildcard InetSocketAddress
            return new InetSocketAddress(addr, port);
        }
    }
}
