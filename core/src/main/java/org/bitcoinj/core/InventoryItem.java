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

import com.google.common.base.Objects;

public class InventoryItem {

    /**
     * 4 byte uint32 type field + 32 byte hash
     */
    static final int MESSAGE_LENGTH = 36;

    static final int WITNESS_FLAG = 1 << 30;

    public enum Type {
        Error(0),
        Transaction(1),
        Block(2),
        FilteredBlock(3),
        WitnessBlock(Block.code | WITNESS_FLAG),
        WitnessTransaction(Transaction.code | WITNESS_FLAG),
        FilteredWitnessBlock(FilteredBlock.code | WITNESS_FLAG);

        private int code;
        Type(int code) {
            this.code = code;
        }

        public int code() {
            return code;
        }

        public static Type parse(int code) {
            for (Type type : values()) {
                if (type.code() == code) {
                    return type;
                }
            }
            return null;
        }
    }

    public final Type type;
    public final Sha256Hash hash;

    public InventoryItem(Type type, Sha256Hash hash) {
        this.type = type;
        this.hash = hash;
    }

    @Override
    public String toString() {
        return type + ": " + hash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InventoryItem other = (InventoryItem) o;
        return type == other.type && hash.equals(other.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(type, hash);
    }

    InventoryItem toWitnessItem() {
        return new InventoryItem(Type.parse(type.code() | WITNESS_FLAG), hash);
    }
}
