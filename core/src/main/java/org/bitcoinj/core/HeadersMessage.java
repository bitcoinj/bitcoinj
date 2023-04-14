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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * <p>A protocol message that contains a repeated series of block headers, sent in response to the "getheaders" command.
 * This is useful when you want to traverse the chain but know you don't care about the block contents, for example,
 * because you have a freshly created wallet with no keys.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class HeadersMessage extends BaseMessage {
    private static final Logger log = LoggerFactory.getLogger(HeadersMessage.class);

    // The main client will never send us more than this number of headers.
    public static final int MAX_HEADERS = 2000;

    private List<Block> blockHeaders;

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static HeadersMessage read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        VarInt numHeadersVarInt = VarInt.read(payload);
        check(numHeadersVarInt.fitsInt(), BufferUnderflowException::new);
        int numHeaders = numHeadersVarInt.intValue();
        if (numHeaders > MAX_HEADERS)
            throw new ProtocolException("Too many headers: got " + numHeaders + " which is larger than " +
                    MAX_HEADERS);

        List<Block> blockHeaders = new ArrayList<>();
        for (int i = 0; i < numHeaders; ++i) {
            final Block newBlockHeader = Block.read(payload);
            if (newBlockHeader.hasTransactions()) {
                throw new ProtocolException("Block header does not end with a null byte");
            }
            blockHeaders.add(newBlockHeader);
        }

        if (log.isDebugEnabled()) {
            for (int i = 0; i < numHeaders; ++i) {
                log.debug(blockHeaders.get(i).toString());
            }
        }
        return new HeadersMessage(blockHeaders);
    }

    public HeadersMessage(Block... headers) throws ProtocolException {
        super();
        blockHeaders = Arrays.asList(headers);
    }

    public HeadersMessage(List<Block> headers) throws ProtocolException {
        super();
        blockHeaders = headers;
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(VarInt.of(blockHeaders.size()).serialize());
        for (Block header : blockHeaders) {
            header.cloneAsHeader().bitcoinSerializeToStream(stream);
            stream.write(0);
        }
    }

    public List<Block> getBlockHeaders() {
        return blockHeaders;
    }
}
