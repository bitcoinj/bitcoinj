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

package org.bitcoinj.core;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * A VersionMessage holds information exchanged during connection setup with another peer. Most of the fields are not
 * particularly interesting. The subVer field, since BIP 14, acts as a User-Agent string would. You can and should 
 * append to or change the subVer for your own software so other implementations can identify it, and you can look at
 * the subVer field received from other nodes to see what they are running. <p>
 *
 * After creating yourself a VersionMessage, you can pass it to {@link PeerGroup#setVersionMessage(VersionMessage)}
 * to ensure it will be used for each new connection.
 */
public class VersionMessage extends Message {
    private static final long serialVersionUID = 7313594258967483180L;

    /** A services flag that denotes whether the peer has a copy of the block chain or not. */
    public static final int NODE_NETWORK = 1;
    /** A flag that denotes whether the peer supports the getutxos message or not. */
    public static final int NODE_GETUTXOS = 2;

    /**
     * The version number of the protocol spoken.
     */
    public int clientVersion;
    /**
     * Flags defining what optional services are supported.
     */
    public long localServices;
    /**
     * What the other side believes the current time to be, in seconds.
     */
    public long time;
    /**
     * What the other side believes the address of this program is. Not used.
     */
    public PeerAddress myAddr;
    /**
     * What the other side believes their own address is. Not used.
     */
    public PeerAddress theirAddr;
    /**
     * User-Agent as defined in <a href="https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki">BIP 14</a>.
     * The official client sets it to something like "/Satoshi:0.9.1/".
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

    /** The version of this library release, as a string. */
    public static final String BITCOINJ_VERSION = "0.12.3";
    /** The value that is prepended to the subVer field of this application. */
    public static final String LIBRARY_SUBVER = "/bitcoinj:" + BITCOINJ_VERSION + "/";

    public VersionMessage(NetworkParameters params, byte[] payload) throws ProtocolException {
        super(params, payload, 0);
    }

    // It doesn't really make sense to ever lazily parse a version message or to retain the backing bytes.
    // If you're receiving this on the wire you need to check the protocol version and it will never need to be sent
    // back down the wire.
    
    public VersionMessage(NetworkParameters params, int newBestHeight) {
        super(params);
        clientVersion = NetworkParameters.PROTOCOL_VERSION;
        localServices = 0;
        time = System.currentTimeMillis() / 1000;
        // Note that the official client doesn't do anything with these, and finding out your own external IP address
        // is kind of tricky anyway, so we just put nonsense here for now.
        try {
            // We hard-code the IPv4 localhost address here rather than use InetAddress.getLocalHost() because some
            // mobile phones have broken localhost DNS entries, also, this is faster.
            final byte[] localhost = { 127, 0, 0, 1 };
            myAddr = new PeerAddress(InetAddress.getByAddress(localhost), params.getPort(), 0);
            theirAddr = new PeerAddress(InetAddress.getByAddress(localhost), params.getPort(), 0);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Cannot happen (illegal IP length).
        }
        subVer = LIBRARY_SUBVER;
        bestHeight = newBestHeight;
        relayTxesBeforeFilter = true;

        length = 85;
        if (protocolVersion > 31402)
            length += 8;
        length += VarInt.sizeOf(subVer.length()) + subVer.length();
    }

    @Override
    protected void parseLite() throws ProtocolException {
        // NOP.  VersionMessage is never lazy parsed.
    }

    @Override
    public void parse() throws ProtocolException {
        if (parsed)
            return;
        parsed = true;

        clientVersion = (int) readUint32();
        localServices = readUint64().longValue();
        time = readUint64().longValue();
        myAddr = new PeerAddress(params, payload, cursor, 0);
        cursor += myAddr.getMessageSize();
        theirAddr = new PeerAddress(params, payload, cursor, 0);
        cursor += theirAddr.getMessageSize();
        // uint64 localHostNonce  (random data)
        // We don't care about the localhost nonce. It's used to detect connecting back to yourself in cases where
        // there are NATs and proxies in the way. However we don't listen for inbound connections so it's irrelevant.
        readUint64();
        try {
            // Initialize default values for flags which may not be sent by old nodes
            subVer = "";
            bestHeight = 0;
            relayTxesBeforeFilter = true;
            if (!hasMoreBytes())
                return;
            //   string subVer  (currently "")
            subVer = readStr();
            if (!hasMoreBytes())
                return;
            //   int bestHeight (size of known block chain).
            bestHeight = readUint32();
            if (!hasMoreBytes())
                return;
            relayTxesBeforeFilter = readBytes(1)[0] != 0;
        } finally {
            length = cursor - offset;
        }
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream buf) throws IOException {
        Utils.uint32ToByteStreamLE(clientVersion, buf);
        Utils.uint32ToByteStreamLE(localServices, buf);
        Utils.uint32ToByteStreamLE(localServices >> 32, buf);
        Utils.uint32ToByteStreamLE(time, buf);
        Utils.uint32ToByteStreamLE(time >> 32, buf);
        try {
            // My address.
            myAddr.bitcoinSerialize(buf);
            // Their address.
            theirAddr.bitcoinSerialize(buf);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Can't happen.
        } catch (IOException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
        // Next up is the "local host nonce", this is to detect the case of connecting
        // back to yourself. We don't care about this as we won't be accepting inbound 
        // connections.
        Utils.uint32ToByteStreamLE(0, buf);
        Utils.uint32ToByteStreamLE(0, buf);
        // Now comes subVer.
        byte[] subVerBytes = subVer.getBytes("UTF-8");
        buf.write(new VarInt(subVerBytes.length).encode());
        buf.write(subVerBytes);
        // Size of known block chain.
        Utils.uint32ToByteStreamLE(bestHeight, buf);
        buf.write(relayTxesBeforeFilter ? 1 : 0);
    }

    /**
     * Returns true if the version message indicates the sender has a full copy of the block chain,
     * or if it's running in client mode (only has the headers).
     */
    public boolean hasBlockChain() {
        return (localServices & NODE_NETWORK) == NODE_NETWORK;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VersionMessage other = (VersionMessage) o;
        return other.bestHeight == bestHeight &&
                other.clientVersion == clientVersion &&
                other.localServices == localServices &&
                other.time == time &&
                other.subVer.equals(subVer) &&
                other.myAddr.equals(myAddr) &&
                other.theirAddr.equals(theirAddr) &&
                other.relayTxesBeforeFilter == relayTxesBeforeFilter;
    }

    @Override
    public int hashCode() {
        return (int) bestHeight ^ clientVersion ^ (int) localServices ^ (int) time ^ subVer.hashCode() ^ myAddr.hashCode()
            ^ theirAddr.hashCode() * (relayTxesBeforeFilter ? 1 : 2);
    }

    /**
     * VersionMessage does not handle cached byte array so should not have a cached checksum.
     */
    @Override
    byte[] getChecksum() {
        throw new UnsupportedOperationException();
    }

    /**
     * VersionMessage does not handle cached byte array so should not have a cached checksum.
     */
    @Override
    void setChecksum(byte[] checksum) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n");
        sb.append("client version: ").append(clientVersion).append("\n");
        sb.append("local services: ").append(localServices).append("\n");
        sb.append("time:           ").append(time).append("\n");
        sb.append("my addr:        ").append(myAddr).append("\n");
        sb.append("their addr:     ").append(theirAddr).append("\n");
        sb.append("sub version:    ").append(subVer).append("\n");
        sb.append("best height:    ").append(bestHeight).append("\n");
        sb.append("delay tx relay: ").append(!relayTxesBeforeFilter).append("\n");
        return sb.toString();
    }

    public VersionMessage duplicate() {
        VersionMessage v = new VersionMessage(params, (int) bestHeight);
        v.clientVersion = clientVersion;
        v.localServices = localServices;
        v.time = time;
        v.myAddr = myAddr;
        v.theirAddr = theirAddr;
        v.subVer = subVer;
        v.relayTxesBeforeFilter = relayTxesBeforeFilter;
        return v;
    }

    /**
     * Appends the given user-agent information to the subVer field. The subVer is composed of a series of
     * name:version pairs separated by slashes in the form of a path. For example a typical subVer field for BitCoinJ
     * users might look like "/BitCoinJ:0.4-SNAPSHOT/MultiBit:1.2/" where libraries come further to the left.<p>
     *
     * There can be as many components as you feel a need for, and the version string can be anything, but it is
     * recommended to use A.B.C where A = major, B = minor and C = revision for software releases, and dates for
     * auto-generated source repository snapshots. A valid subVer begins and ends with a slash, therefore name
     * and version are not allowed to contain such characters. <p>
     *
     * Anything put in the "comments" field will appear in brackets and may be used for platform info, or anything
     * else. For example, calling <tt>appendToSubVer("MultiBit", "1.0", "Windows")</tt> will result in a subVer being
     * set of "/BitCoinJ:1.0/MultiBit:1.0(Windows)/". Therefore the / ( and ) characters are reserved in all these
     * components. If you don't want to add a comment (recommended), pass null.<p>
     *
     * See <a href="https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki">BIP 14</a> for more information.
     *
     * @param comments Optional (can be null) platform or other node specific information.
     * @throws IllegalArgumentException if name, version or comments contains invalid characters.
     */
    public void appendToSubVer(String name, String version, @Nullable String comments) {
        checkSubVerComponent(name);
        checkSubVerComponent(version);
        if (comments != null) {
            checkSubVerComponent(comments);
            subVer = subVer.concat(String.format("%s:%s(%s)/", name, version, comments));
        } else {
            subVer = subVer.concat(String.format("%s:%s/", name, version));
        }
    }

    private static void checkSubVerComponent(String component) {
        if (component.contains("/") || component.contains("(") || component.contains(")"))
            throw new IllegalArgumentException("name contains invalid characters");
    }

    /**
     * Returns true if the clientVersion field is >= Pong.MIN_PROTOCOL_VERSION. If it is then ping() is usable.
     */
    public boolean isPingPongSupported() {
        return clientVersion >= Pong.MIN_PROTOCOL_VERSION;
    }

    /**
     * Returns true if the clientVersion field is >= FilteredBlock.MIN_PROTOCOL_VERSION. If it is then Bloom filtering
     * is available and the memory pool of the remote peer will be queried when the downloadData property is true.
     */
    public boolean isBloomFilteringSupported() {
        return clientVersion >= FilteredBlock.MIN_PROTOCOL_VERSION;
    }

    /** Returns true if the protocol version and service bits both indicate support for the getutxos message. */
    public boolean isGetUTXOsSupported() {
        return clientVersion >= GetUTXOsMessage.MIN_PROTOCOL_VERSION &&
                (localServices & NODE_GETUTXOS) == NODE_GETUTXOS;
    }
}
