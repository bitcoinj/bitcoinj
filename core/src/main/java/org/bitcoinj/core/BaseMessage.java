/*
 * Copyright by the original author or authors.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * A Message is a data structure that can be serialized/deserialized using the Bitcoin serialization format.
 * Specific types of messages that are used both in the blockchain, and on the wire, are derived from this
 * class.
 * <p>
 * Instances of this class are not safe for use by multiple threads.
 */
public abstract class BaseMessage implements Message {
    private static final Logger log = LoggerFactory.getLogger(BaseMessage.class);

    // These methods handle the serialization/deserialization using the custom Bitcoin protocol.

    /**
     * <p>Serialize this message to a byte array that conforms to the bitcoin wire protocol.</p>
     *
     * @return serialized data in Bitcoin protocol format
     */
    @Override
    public final byte[] serialize() {
        // No cached array available so serialize parts by stream.
        ByteArrayOutputStream stream = new ByteArrayOutputStream(100); // initial size just a guess
        try {
            bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    /**
     * Serializes this message to the provided stream. If you just want the raw bytes use {@link #serialize()}.
     */
    protected abstract void bitcoinSerializeToStream(OutputStream stream) throws IOException;

    /**
     * Return the size of the serialized message. Note that if the message was deserialized from a payload, this
     * size can differ from the size of the original payload.
     * @return size of this object when serialized (in bytes)
     */
    @Override
    public int messageSize() {
        return serialize().length;
    }
}
