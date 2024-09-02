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

/**
 * A Message is a data structure that can be serialized/deserialized using the Bitcoin serialization format.
 * Classes that can be serialized to the blockchain or P2P protocol should implement this interface.
 */
public interface Message {
    /**
     * Maximum size of a Bitcoin P2P Message (32 MB)
     */
    int MAX_SIZE = 0x02000000;

    /**
     * Return the size of the serialized message. Note that if the message was deserialized from a payload, this
     * size can differ from the size of the original payload.
     *
     * @return size of this object when serialized (in bytes)
     */
    int messageSize();

    /**
     * Serialize this message to a byte array that conforms to the Bitcoin wire protocol.
     *
     * @return serialized data in Bitcoin protocol format
     */
    byte[] serialize();
}
