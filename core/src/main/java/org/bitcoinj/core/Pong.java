/**
 * Copyright 2012 Matt Corallo
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

import java.io.IOException;
import java.io.OutputStream;

public class Pong extends Message {
    /** The smallest protocol version that supports the pong response (BIP 31). Anything beyond version 60000. */
    public static final int MIN_PROTOCOL_VERSION = 60001;

    private long nonce;

    public Pong(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }
    
    /**
     * Create a Pong with a nonce value.
     * Only use this if the remote node has a protocol version > 60000
     */
    public Pong(long nonce) {
        this.nonce = nonce;
    }
    
    @Override
    void parse() throws ProtocolException {
        nonce = readInt64();
        length = 8;
    }
    
    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        Utils.int64ToByteStreamLE(nonce, stream);
    }
    
    @Override
    protected void parseLite() {
    }

    /** Returns the nonce sent by the remote peer. */
    public long getNonce() {
        return nonce;
    }
}
