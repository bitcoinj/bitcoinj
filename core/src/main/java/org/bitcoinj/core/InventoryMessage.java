/*
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

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * <p>Represents the "inv" P2P network message. An inv contains a list of hashes of either blocks or transactions. It's
 * a bandwidth optimization - on receiving some data, a (fully validating) peer sends every connected peer an inv
 * containing the hash of what it saw. It'll only transmit the full thing if a peer asks for it with a
 * {@link GetDataMessage}.</p>
 *
 * <p>Instances of this class -- that use deprecated methods -- are not safe for use by multiple threads.</p>
 */
public class InventoryMessage extends ListMessage {

    /** A hard coded constant in the protocol. */
    public static final int MAX_INV_SIZE = 50000;

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static InventoryMessage read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        return new InventoryMessage(readItems(payload));
    }

    @Deprecated
    protected InventoryMessage() {
        super();
    }

    protected InventoryMessage(List<InventoryItem> items) {
        super(items);
    }

    public static InventoryMessage ofBlocks(List<Block> blocks) {
        checkArgument(!blocks.isEmpty());
        return new InventoryMessage(blocks.stream()
                .map(InventoryItem::new)
                .collect(Collectors.toList()));
    }

    public static InventoryMessage ofBlocks(Block ...blocks) {
        return ofBlocks(Arrays.asList(blocks));
    }

    public static InventoryMessage ofTransactions(List<Transaction> transactions) {
        checkArgument(!transactions.isEmpty());
        return new InventoryMessage(transactions.stream()
                .map(InventoryItem::new)
                .collect(Collectors.toList()));
    }

    public static InventoryMessage ofTransactions(Transaction ...transactions) {
        return ofTransactions(Arrays.asList(transactions));
    }

    /**
     * @deprecated Use a constructor or factoring
     */
    @Deprecated
    public void addBlock(Block block) {
        addItem(new InventoryItem(block));
    }

    /**
     * @deprecated Use a constructor or factoring
     */
    @Deprecated
    public void addTransaction(Transaction tx) {
        addItem(new InventoryItem(tx));
    }

    /**
     * Creates a new inv message for the given transactions.
     * @deprecated Use {@link #ofTransactions(Transaction...)}
     */
    @Deprecated
    public static InventoryMessage with(Transaction... txns) {
        return ofTransactions(txns);
    }
}
