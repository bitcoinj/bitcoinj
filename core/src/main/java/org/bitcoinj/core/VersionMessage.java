/*
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

package org.bitcoinj.core;

import com.google.common.net.InetAddresses;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.Buffers;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.base.internal.ByteUtils;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Objects;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * <p>A VersionMessage holds information exchanged during connection setup with another peer. Most of the fields are not
 * particularly interesting. The subVer field, since BIP 14, acts as a User-Agent string would. You can and should 
 * append to or change the subVer for your own software so other implementations can identify it, and you can look at
 * the subVer field received from other nodes to see what they are running.</p>
 *
 * <p>After creating yourself a VersionMessage, you can pass it to {@link PeerGroup#setVersionMessage(VersionMessage)}
 * to ensure it will be used for each new connection.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class VersionMessage extends BaseMessage {

    /** The version of this library release, as a string. */
    public static final String BITCOINJ_VERSION = "0.17-SNAPSHOT";
    /** The value that is prepended to the subVer field of this application. */
    public static final String LIBRARY_SUBVER = "/bitcoinj:" + BITCOINJ_VERSION + "/";

    /** @deprecated use {@link Services#NODE_NETWORK} */
    @Deprecated
    public static final int NODE_NETWORK = 1 << 0;
    /** @deprecated use {@link Services#NODE_BLOOM} */
    @Deprecated
    public static final int NODE_BLOOM = 1 << 2;
    /** @deprecated use {@link Services#NODE_WITNESS} */
    @Deprecated
    public static final int NODE_WITNESS = 1 << 3;
    /** @deprecated use {@link Services#NODE_NETWORK_LIMITED} */
    @Deprecated
    public static final int NODE_NETWORK_LIMITED = 1 << 10;
    /** @deprecated use {@link Services#NODE_BITCOIN_CASH} */
    @Deprecated
    public static final int NODE_BITCOIN_CASH = 1 << 5;

    /**
     * The version number of the protocol spoken.
     */
    public int clientVersion;
    /**
     * Flags defining what optional services are supported.
     */
    public Services localServices;
    /**
     * What the other side believes the current time to be.
     */
    public Instant time;
    /**
     * The services supported by the receiving node as perceived by the transmitting node.
     */
    public Services receivingServices;
    /**
     * The network address of the receiving node as perceived by the transmitting node
     */
    public InetSocketAddress receivingAddr;
    /**
     * User-Agent as defined in <a href="https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki">BIP 14</a>.
     * Bitcoin Core sets it to something like "/Satoshi:0.9.1/".
     */
    public String subVer;
    /**
     * How many blocks are in the chain, according to the other side.
     */
    public long bestHeight;
    /**
     * Whether or not to relay tx invs before a filter is received.
     * See <a href="https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#extensions-to-existing-messages">BIP 37</a>.
     */
    public boolean relayTxesBeforeFilter;

    private static final int NETADDR_BYTES = Services.BYTES + /* IPv6 */  16 + /* port */ Short.BYTES;

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static VersionMessage read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        int clientVersion = (int) ByteUtils.readUint32(payload);
        check(clientVersion >= ProtocolVersion.MINIMUM.intValue(),
                ProtocolException::new);
        Services localServices = Services.read(payload);
        Instant time = Instant.ofEpochSecond(ByteUtils.readInt64(payload));
        Services receivingServices = Services.read(payload);
        InetAddress receivingInetAddress = PeerAddress.getByAddress(Buffers.readBytes(payload, 16));
        int receivingPort = ByteUtils.readUint16BE(payload);
        InetSocketAddress receivingAddr = new InetSocketAddress(receivingInetAddress, receivingPort);
        Buffers.skipBytes(payload, NETADDR_BYTES); // addr_from
        // uint64 localHostNonce (random data)
        // We don't care about the localhost nonce. It's used to detect connecting back to yourself in cases where
        // there are NATs and proxies in the way. However we don't listen for inbound connections so it's
        // irrelevant.
        Buffers.skipBytes(payload, 8);
        // string subVer (currently "")
        String subVer = Buffers.readLengthPrefixedString(payload);
        // int bestHeight (size of known block chain).
        long bestHeight = ByteUtils.readUint32(payload);
        boolean relayTxesBeforeFilter = clientVersion >= ProtocolVersion.BLOOM_FILTER.intValue() ?
                payload.get() != 0 :
                true;
        return new VersionMessage(clientVersion, localServices, time, receivingServices, receivingAddr, subVer,
                bestHeight, relayTxesBeforeFilter);
    }

    /**
     * Construct own version message from given {@link NetworkParameters} and our best height of the chain.
     *
     * @param params     network parameters to construct own version message from
     * @param bestHeight our best height to announce
     */
    public VersionMessage(NetworkParameters params, int bestHeight) {
        this.clientVersion = ProtocolVersion.CURRENT.intValue();
        this.localServices = Services.none();
        this.time = TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS);
        InetAddress localhost = InetAddresses.forString("127.0.0.1");
        this.receivingServices = Services.none();
        this.receivingAddr = new InetSocketAddress(localhost, params.getPort());
        this.subVer = LIBRARY_SUBVER;
        this.bestHeight = bestHeight;
        this.relayTxesBeforeFilter = true;
    }

    private VersionMessage(int clientVersion, Services localServices, Instant time, Services receivingServices,
                           InetSocketAddress receivingAddr, String subVer, long bestHeight,
                           boolean relayTxesBeforeFilter) {
        this.clientVersion = clientVersion;
        this.localServices = localServices;
        this.time = time;
        this.receivingServices = receivingServices;
        this.receivingAddr = receivingAddr;
        this.subVer = subVer;
        this.bestHeight = bestHeight;
        this.relayTxesBeforeFilter = relayTxesBeforeFilter;
    }

    /**
     * Gets the client version.
     *
     * @return client version
     */
    public int clientVersion() {
        return clientVersion;
    }

    /**
     * Get the service bitfield that represents the node services being provided.
     *
     * @return service bitfield
     */
    public Services services() {
        return localServices;
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream buf) throws IOException {
        ByteUtils.writeInt32LE(clientVersion, buf);
        buf.write(localServices.serialize());
        ByteUtils.writeInt64LE(time.getEpochSecond(), buf);
        buf.write(receivingServices.serialize());
        buf.write(PeerAddress.mapIntoIPv6(receivingAddr.getAddress().getAddress()));
        ByteUtils.writeInt16BE(receivingAddr.getPort(), buf);
        buf.write(new byte[NETADDR_BYTES]); // addr_from
        // Next up is the "local host nonce", this is to detect the case of connecting
        // back to yourself. We don't care about this as we won't be accepting inbound
        // connections.
        ByteUtils.writeInt32LE(0, buf);
        ByteUtils.writeInt32LE(0, buf);
        // Now comes subVer.
        byte[] subVerBytes = subVer.getBytes(StandardCharsets.UTF_8);
        buf.write(VarInt.of(subVerBytes.length).serialize());
        buf.write(subVerBytes);
        // Size of known block chain.
        ByteUtils.writeInt32LE(bestHeight, buf);
        buf.write(relayTxesBeforeFilter ? 1 : 0);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VersionMessage other = (VersionMessage) o;
        return other.bestHeight == bestHeight &&
                other.clientVersion == clientVersion &&
                other.localServices == localServices &&
                other.time.equals(time) &&
                other.subVer.equals(subVer) &&
                other.receivingServices.equals(receivingServices) &&
                other.receivingAddr.equals(receivingAddr) &&
                other.relayTxesBeforeFilter == relayTxesBeforeFilter;
    }

    @Override
    public int hashCode() {
        return Objects.hash(bestHeight, clientVersion, localServices,
            time, subVer, receivingServices, receivingAddr, relayTxesBeforeFilter);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("\n");
        builder.append("client version: ").append(clientVersion).append("\n");
        if (localServices.hasAny())
            builder.append("local services: ").append(localServices);
        builder.append("\n");
        builder.append("time:           ").append(TimeUtils.dateTimeFormat(time)).append("\n");
        builder.append("receiving svc:  ").append(receivingServices).append("\n");
        builder.append("receiving addr: ").append(receivingAddr).append("\n");
        builder.append("sub version:    ").append(subVer).append("\n");
        builder.append("best height:    ").append(bestHeight).append("\n");
        builder.append("delay tx relay: ").append(!relayTxesBeforeFilter).append("\n");
        return builder.toString();
    }

    public VersionMessage duplicate() {
        return new VersionMessage(clientVersion, localServices, time, receivingServices, receivingAddr, subVer,
                bestHeight, relayTxesBeforeFilter);
    }

    /**
     * <p>Appends the given user-agent information to the subVer field. The subVer is composed of a series of
     * name:version pairs separated by slashes in the form of a path. For example a typical subVer field for bitcoinj
     * users might look like "/bitcoinj:0.13/MultiBit:1.2/" where libraries come further to the left.</p>
     *
     * <p>There can be as many components as you feel a need for, and the version string can be anything, but it is
     * recommended to use A.B.C where A = major, B = minor and C = revision for software releases, and dates for
     * auto-generated source repository snapshots. A valid subVer begins and ends with a slash, therefore name
     * and version are not allowed to contain such characters.</p>
     *
     * <p>Anything put in the "comments" field will appear in brackets and may be used for platform info, or anything
     * else. For example, calling {@code appendToSubVer("MultiBit", "1.0", "Windows")} will result in a subVer being
     * set of "/bitcoinj:1.0/MultiBit:1.0(Windows)/". Therefore the / ( and ) characters are reserved in all these
     * components. If you don't want to add a comment (recommended), pass null.</p>
     *
     * <p>See <a href="https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki">BIP 14</a> for more information.</p>
     *
     * @param comments Optional (can be null) platform or other node specific information.
     * @throws IllegalArgumentException if name, version or comments contains invalid characters.
     */
    public void appendToSubVer(String name, String version, @Nullable String comments) {
        checkSubVerComponent(name);
        checkSubVerComponent(version);
        if (comments != null) {
            checkSubVerComponent(comments);
            subVer = subVer.concat(String.format(Locale.US, "%s:%s(%s)/", name, version, comments));
        } else {
            subVer = subVer.concat(String.format(Locale.US, "%s:%s/", name, version));
        }
    }

    private static void checkSubVerComponent(String component) {
        if (component.contains("/") || component.contains("(") || component.contains(")"))
            throw new IllegalArgumentException("name contains invalid characters");
    }

    /** @deprecated just assume {@link Ping} and {@link Pong} are supported */
    @Deprecated
    public boolean isPingPongSupported() {
        return true;
    }

    /** @deprecated use {@link Services#of(long)} and {@link Services#toString()} */
    @Deprecated
    public static String toStringServices(long services) {
        return Services.of(services).toString();
    }
}
