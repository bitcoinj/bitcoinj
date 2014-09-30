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

package org.bitcoinj.core;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>Represents the "inv" P2P network message. An inv contains a list of hashes of either blocks or transactions. It's
 * a bandwidth optimization - on receiving some data, a (fully validating) peer sends every connected peer an inv
 * containing the hash of what it saw. It'll only transmit the full thing if a peer asks for it with a
 * {@link GetDataMessage}.</p>
 */
public class InventoryMessage extends ListMessage {
    private static final long serialVersionUID = -7050246551646107066L;

    /** A hard coded constant in the protocol. */
    public static final int MAX_INV_SIZE = 50000;

    public InventoryMessage(NetworkParameters params, byte[] bytes) throws ProtocolException {
        super(params, bytes);
    }

    /**
     * Deserializes an 'inv' message.
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public InventoryMessage(NetworkParameters params, byte[] payload, boolean parseLazy, boolean parseRetain, int length)
            throws ProtocolException {
        super(params, payload, parseLazy, parseRetain, length);
    }

    public InventoryMessage(NetworkParameters params) {
        super(params);
    }

    public void addBlock(Block block) {
        addItem(new InventoryItem(InventoryItem.Type.Block, block.getHash()));
    }

    public void addTransaction(Transaction tx) {
        addItem(new InventoryItem(InventoryItem.Type.Transaction, tx.getHash()));
    }

    /** Creates a new inv message for the given transactions. */
    public static InventoryMessage with(Transaction... txns) {
        checkArgument(txns.length > 0);
        InventoryMessage result = new InventoryMessage(txns[0].getParams());
        for (Transaction tx : txns)
            result.addTransaction(tx);
        return result;
    }
}
