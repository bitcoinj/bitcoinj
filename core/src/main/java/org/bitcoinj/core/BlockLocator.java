/*
 * Copyright (c) 2018.
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.bitcoinj.core;
import com.google.common.collect.ImmutableList;

import java.util.List;

public final class BlockLocator {
    private ImmutableList<Sha256Hash> hashes;

    public BlockLocator() {
        hashes = ImmutableList.of();
    }

    public BlockLocator(ImmutableList<Sha256Hash> hashes) {
        this.hashes = hashes;
    }

    public BlockLocator add(Sha256Hash hash) {
        return new BlockLocator(new ImmutableList.Builder<Sha256Hash>().addAll(this.hashes).add(hash).build());
    }

    public int size() {
        return hashes.size();
    }

    public List<Sha256Hash> getHashes() {
        return hashes;
    }

    public boolean containsAll(BlockLocator other) {
        return hashes.equals(other.getHashes());
    }

    @Override
    public String toString() {
        return "Block locator with " + size() + " blocks \n " + Utils.SPACE_JOINER.join(hashes);
    }

    @Override
    public int hashCode() {
        int hashCode = 0;
        for (Sha256Hash i : hashes) {
            hashCode ^= i.hashCode();
        }
        return hashCode;
    }

    @Override
    public boolean equals(Object o) {
        if (o != null && o instanceof BlockLocator) {
            return ((BlockLocator) o).getHashes().equals(hashes);
        }
        return false;
    }
}
