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

package org.bitcoinj.core.listeners;

import org.bitcoinj.core.AddressMessage;
import org.bitcoinj.core.Peer;

/**
 * <p>Implementors can listen to addresses being received from remote peers.</p>
 */
public interface AddressEventListener {

    /**
     * Called when a peer receives an {@code addr} or {@code addrv2} message, usually in response to a
     * {@code getaddr} message.
     *
     * @param peer    the peer that received the addr or addrv2 message
     * @param message the addr or addrv2 message that was received
     */
    void onAddr(Peer peer, AddressMessage message);
}
