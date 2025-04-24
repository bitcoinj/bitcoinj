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

import com.google.common.base.MoreObjects;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * Represents the "inv" P2P network message. An inv contains a list of hashes of either blocks or transactions. It's
 * a bandwidth optimization - on receiving some data, a (fully validating) peer sends every connected peer an inv
 * containing the hash of what it saw. It'll only transmit the full thing if a peer asks for it with a
 * {@link GetDataMessage}.
 */
public class InventoryMessage implements ListMessage {

    /** A hard coded constant in the protocol. */
    public static final int MAX_INV_SIZE = 50000;
    private final List<InventoryItem> items;

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static InventoryMessage read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        return new InventoryMessage(ListMessage.readItems(payload));
    }

    protected InventoryMessage(List<InventoryItem> items) {
        this.items = items;    // TODO: unmodifiable defensive copy
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

    @Override
    public List<InventoryItem> items() {
        return items;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return items.equals(((InventoryMessage)o).items);
    }

    @Override
    public int hashCode() {
        return items.hashCode();
    }

    @Override
    public String toString() {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this);
        helper.addValue(items);
        return helper.toString();
    }
}
