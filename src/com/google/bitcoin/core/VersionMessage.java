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

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class VersionMessage extends Message {
    private static final long serialVersionUID = 7313594258967483180L;

    /**
     * A services flag that denotes whether the peer has a copy of the block chain or not.
     */
    public static final int NODE_NETWORK = 1;

    /** The version number of the protocol spoken. */
    public int clientVersion;
    /** Flags defining what is supported. Right now {@link #NODE_NETWORK} is the only flag defined. */
    public long localServices;
    /** What the other side believes the current time to be, in seconds. */
    public long time;
    /** What the other side believes the address of this program is. Not used. */
    public PeerAddress myAddr;
    /** What the other side believes their own address is. Not used. */
    public PeerAddress theirAddr;
    /**
     * An additional string that today the official client sets to the empty string. We treat it as something like an
     * HTTP User-Agent header.
     */
    public String subVer;
    /** How many blocks are in the chain, according to the other side. */
    public long bestHeight;

    public VersionMessage(NetworkParameters params, byte[] msg) throws ProtocolException {
        super(params, msg, 0);
    }

    public VersionMessage(NetworkParameters params, int newBestHeight) {
        super(params);
        clientVersion = NetworkParameters.PROTOCOL_VERSION;
        localServices = 0;
        time = System.currentTimeMillis() / 1000;
        // Note that the official client doesn't do anything with these, and finding out your own external IP address
        // is kind of tricky anyway, so we just put nonsense here for now.
        try {
            myAddr = new PeerAddress(InetAddress.getLocalHost(), params.port, 0);
            theirAddr = new PeerAddress(InetAddress.getLocalHost(), params.port, 0);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
        subVer = "BitCoinJ 0.3-SNAPSHOT";
        bestHeight = newBestHeight;
    }
    
    @Override
    public void parse() throws ProtocolException {
        clientVersion = (int) readUint32();
        localServices = readUint64().longValue();
        time = readUint64().longValue();
        myAddr = new PeerAddress(params, bytes, cursor, 0);
        cursor += myAddr.getMessageSize();
        theirAddr = new PeerAddress(params, bytes, cursor, 0);
        cursor += theirAddr.getMessageSize();
        // uint64 localHostNonce  (random data)
        // We don't care about the localhost nonce. It's used to detect connecting back to yourself in cases where
        // there are NATs and proxies in the way. However we don't listen for inbound connections so it's irrelevant.
        readUint64();
        //   string subVer  (currently "")
        subVer = readStr();
        //   int bestHeight (size of known block chain).
        bestHeight = readUint32();
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
            myAddr.bitcoinSerializeToStream(buf);
            // Their address.
            theirAddr.bitcoinSerializeToStream(buf);
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
    }

    /**
     * Returns true if the version message indicates the sender has a full copy of the block chain,
     * or if it's running in client mode (only has the headers).
     */
    public boolean hasBlockChain() {
        return (localServices & NODE_NETWORK) == NODE_NETWORK;
    }
}
