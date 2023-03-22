/*
 * Copyright 2011 Noa Resare
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

import org.bitcoinj.base.internal.ByteUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Random;

/**
 * <p>See <a href="https://github.com/bitcoin/bips/blob/master/bip-0031.mediawiki">BIP31</a> for details.</p>
 *
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class Ping extends Message {
    private long nonce;

    public Ping(ByteBuffer payload) throws ProtocolException {
        super(payload);
    }

    /**
     * Create a Ping with a given nonce value.
     */
    public Ping(long nonce) {
        this.nonce = nonce;
    }

    /**
     * Create a Ping with a random nonce value.
     */
    public Ping() {
        this.nonce = new Random().nextLong();
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        ByteUtils.writeInt64LE(nonce, stream);
    }

    @Override
    protected void parse(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        nonce = ByteUtils.readInt64(payload);
    }

    /** @deprecated returns true */
    @Deprecated
    public boolean hasNonce() {
        return true;
    }

    public long getNonce() {
        return nonce;
    }
}
