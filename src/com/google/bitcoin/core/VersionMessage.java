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
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class VersionMessage extends Message {
    public static final int PROTOCOL_VERSION = 31800;

    public int clientVersion;
    // Flags defining what the other side supports. Right now there's only one flag and it's
    // always set 1 by the official client, but we have to set it to zero as we don't store
    // the block chain. In future there may be more services bits.
    public int localServices = 0;
    public BigInteger time;

    public VersionMessage(NetworkParameters params, byte[] msg) throws ProtocolException {
        super(params, msg, 0);
    }

    public VersionMessage(NetworkParameters params) {
        super(params);
        clientVersion = PROTOCOL_VERSION;
        localServices = 0;
        time = BigInteger.valueOf(System.currentTimeMillis() / 1000);
    }
    
    @Override
    public void parse() throws ProtocolException {
        // There is probably a more Java-ish way to do this.
        clientVersion = (int) readUint32();
        localServices = (int) readUint32();
        time = readUint64();
        // The next fields are:
        //   CAddress my address
        //   CAddress their address
        //   uint64 localHostNonce  (random data)
        //   string subVer  (currently "")
        //   int bestHeight (size of known block chain).
        //
        // However, we don't care about these fields right now.
    }
    
    
    @Override
    public void bitcoinSerializeToStream(OutputStream buf) throws IOException {
        Utils.uint32ToByteStreamLE(clientVersion, buf);
        Utils.uint32ToByteStreamLE(localServices, buf);
        long ltime = time.longValue();
        Utils.uint32ToByteStreamLE(ltime >> 32, buf);
        Utils.uint32ToByteStreamLE(ltime, buf);
        try {
            // Now there are two address structures. Note that the official client doesn't do anything with these, and
            // finding out your own external IP address is kind of tricky anyway, so we just serialize nonsense here.

            // My address.
            new PeerAddress(InetAddress.getLocalHost(), params.port).bitcoinSerializeToStream(buf);
            // Their address.
            new PeerAddress(InetAddress.getLocalHost(), params.port).bitcoinSerializeToStream(buf);
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
        // Now comes an empty string.
        buf.write(0);
        // Size of known block chain. Claim we never saw any blocks.
        Utils.uint32ToByteStreamLE(0, buf);
    }
}
