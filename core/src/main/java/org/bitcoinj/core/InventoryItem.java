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

import org.bitcoinj.base.Sha256Hash;

import java.util.Objects;

public class InventoryItem {
    
    /**
     * 4 byte uint32 type field + 32 byte hash
     */
    static final int MESSAGE_LENGTH = 36;
    
    public enum Type {
        ERROR(0x0), TRANSACTION(0x1), BLOCK(0x2),
        // BIP37 extension:
        FILTERED_BLOCK(0x3),
        // BIP44 extensions:
        WITNESS_TRANSACTION(0x40000001), WITNESS_BLOCK(0x40000002), WITNESS_FILTERED_BLOCK(0x40000003);

        public final int code;

        Type(int code) {
            this.code = code;
        }

        public static Type ofCode(int code) {
            for (Type type : values())
                if (type.code == code)
                    return type;
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
        return Objects.hash(type, hash);
    }
}
