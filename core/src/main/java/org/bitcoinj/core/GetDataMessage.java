/*
 * Copyright 2011 Google Inc.
 * Copyright 2019 Andreas Schildbach
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
import org.bitcoinj.base.Sha256Hash;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;

/**
 * Represents the "getdata" P2P network message, which requests the contents of blocks or transactions given their
 * hashes.
 */
public class GetDataMessage implements ListMessage {
    private final List<InventoryItem> items;

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static GetDataMessage read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        return new GetDataMessage(ListMessage.readItems(payload));
    }

    GetDataMessage(List<InventoryItem> items) {
        this.items = items;    // TODO: unmodifiable defensive copy
    }

    public static GetDataMessage ofBlock(Sha256Hash blockHash, boolean includeWitness) {
        return new GetDataMessage(Collections.singletonList(
                    new InventoryItem(includeWitness
                            ? InventoryItem.Type.WITNESS_BLOCK
                            : InventoryItem.Type.BLOCK,
                            blockHash)));
    }

    public static GetDataMessage ofTransaction(Sha256Hash txId, boolean includeWitness) {
        return new GetDataMessage(Collections.singletonList(
                new InventoryItem(includeWitness
                        ? InventoryItem.Type.WITNESS_TRANSACTION
                        : InventoryItem.Type.TRANSACTION,
                        txId)));
    }

    public Sha256Hash getHashOf(int i) {
        return getItems().get(i).hash;
    }

    @Override
    public List<InventoryItem> items() {
        return items;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return items.equals(((GetDataMessage)o).items);
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
