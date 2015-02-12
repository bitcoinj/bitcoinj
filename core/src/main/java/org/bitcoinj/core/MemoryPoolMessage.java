/*
 * Copyright 2012 Google Inc.
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

/**
 * The "mempool" message asks a remote peer to announce all transactions in its memory pool, possibly restricted by
 * any Bloom filter set on the connection. The list of transaction hashes comes back in an inv message. Note that
 * this is different to the {@link MemoryPool} object which doesn't try to keep track of all pending transactions,
 * it's just a holding area for transactions that a part of the app may find interesting. The mempool message has
 * no fields.
 */
public class MemoryPoolMessage extends Message {
    @Override
    void parse() throws ProtocolException {}

    @Override
    protected void parseLite() throws ProtocolException {}

    @Override
    void bitcoinSerializeToStream(OutputStream stream) throws IOException {}
}
