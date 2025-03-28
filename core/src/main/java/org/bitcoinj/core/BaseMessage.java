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

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

/**
 * A Message is a data structure that can be serialized/deserialized using the Bitcoin serialization format.
 * Specific types of messages that are used both in the blockchain, and on the wire, are derived from this
 * class.
 * <p>
 * Instances of this class are not safe for use by multiple threads.
 */
public abstract class BaseMessage implements Message {
    // These methods handle the serialization/deserialization using the custom Bitcoin protocol.

    /**
     * <p>Serialize this message to a byte array that conforms to the bitcoin wire protocol.</p>
     *
     * @return serialized data in Bitcoin protocol format
     */
    @Override
    public final byte[] serialize() {
        return write(ByteBuffer.allocate(messageSize())).array();
    }

    /**
     * Write this message into the given buffer.
     *
     * @param buf buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the message doesn't fit the remaining buffer
     */
    public abstract ByteBuffer write(ByteBuffer buf) throws BufferOverflowException;
}
