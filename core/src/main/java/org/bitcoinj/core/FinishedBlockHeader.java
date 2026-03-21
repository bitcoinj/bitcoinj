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

import org.bitcoinj.base.Difficulty;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.data.BlockHeaderData;
import org.bitcoinj.core.data.Hashed;
import org.jspecify.annotations.NullMarked;

import java.time.Instant;

/**
 *
 */
@NullMarked
public class FinishedBlockHeader extends Block implements BlockHeaderData, Hashed {
    private final Sha256Hash hash;

    protected FinishedBlockHeader(long version, Sha256Hash prevHash, Sha256Hash merkleRoot, Instant time, Difficulty difficultyTarget, long nonce, Sha256Hash hash) {
        super(version, prevHash, merkleRoot, time, difficultyTarget, nonce, hash);
        this.hash = hash;
    }

    @Override
    public Sha256Hash merkleRoot() {
        return getMerkleRoot();
    }

    @Override
    public long bits() {
        return this.difficultyTarget.compact();
    }

    @Override
    public long nonce() {
        return this.nonce;
    }

    @Override
    public Sha256Hash hash() {
        return hash;
    }
}
