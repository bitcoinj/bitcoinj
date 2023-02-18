/*
 * Copyright 2012 Matt Corallo
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

import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.base.utils.UnknownNetwork;

import java.io.IOException;
import java.io.OutputStream;

/**
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class Pong extends Message {
    private long nonce;

    public Pong(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }
    
    /**
     * Create a Pong with a nonce value.
     * Only use this if the remote node has a protocol version greater than 60000
     */
    public Pong(long nonce) {
        super(UnknownNetwork.UNNECESSARY);
        this.nonce = nonce;
    }
    
    @Override
    protected void parse() throws ProtocolException {
        nonce = readInt64();
        length = 8;
    }
    
    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        ByteUtils.int64ToByteStreamLE(nonce, stream);
    }
    
    /** Returns the nonce sent by the remote peer. */
    public long getNonce() {
        return nonce;
    }
}
