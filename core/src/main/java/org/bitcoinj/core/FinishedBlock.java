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
import org.bitcoinj.core.data.BlockData;
import org.bitcoinj.core.data.BlockHeaderData;
import org.bitcoinj.core.data.Hashed;
import org.jspecify.annotations.NullMarked;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

@NullMarked
public abstract /* sealed */ class FinishedBlock extends Block implements BlockHeaderData, Hashed {
    protected final int version;
    protected final Sha256Hash prevHash;
    protected final Sha256Hash merkleRoot;
    protected final Instant time;
    protected final Difficulty difficulty;
    protected final int nonce;
    protected final Sha256Hash hash;

    // full
    private FinishedBlock(long version, Sha256Hash prevHash, Sha256Hash merkleRoot, Instant time, Difficulty difficultyTarget, long nonce, List<Transaction> transactions, Sha256Hash hash) {
        super(version, prevHash, merkleRoot, time, difficultyTarget, nonce, transactions, hash);
        this.version = (int) version;
        this.prevHash = prevHash;
        this.merkleRoot = merkleRoot;
        this.time = time;
        this.difficulty = difficultyTarget;
        this.nonce = (int) nonce;
        this.hash = hash;
    }

    // header
    private FinishedBlock(long version, Sha256Hash prevHash, Sha256Hash merkleRoot, Instant time, Difficulty difficultyTarget, long nonce, Sha256Hash hash) {
        super(version, prevHash, merkleRoot, time, difficultyTarget, nonce, hash);
        this.version = (int) version;
        this.prevHash = prevHash;
        this.merkleRoot = merkleRoot;
        this.time = time;
        this.difficulty = difficultyTarget;
        this.nonce = (int) nonce;
        this.hash = hash;
    }

    public static class Full extends FinishedBlock implements BlockData {
        private final List<Transaction> transactions;

        public Full(long version, Sha256Hash prevHash, Sha256Hash merkleRoot, Instant time, Difficulty difficultyTarget, long nonce, List<Transaction> transactions, Sha256Hash hash) {
            super(version, prevHash, merkleRoot, time, difficultyTarget, nonce, transactions, hash);
            this.transactions = transactions;
        }

        @Override
        public List<Transaction> transactions() {
            Objects.requireNonNull(this.transactions);
            return this.transactions;
        }

        @Override
        public Block asUnfinished() {
            return new Block(Integer.toUnsignedLong(version), prevHash, merkleRoot, time, difficulty, Integer.toUnsignedLong(nonce), Objects.requireNonNull(transactions), hash);
        }
    }

    public static class Header extends FinishedBlock {
        public Header(long version, Sha256Hash prevHash, Sha256Hash merkleRoot, Instant time, Difficulty difficultyTarget, long nonce, Sha256Hash hash) {
            super(version, prevHash, merkleRoot, time, difficultyTarget, nonce, hash);
        }

        @Override
        public Block asUnfinished() {
            return new Block(Integer.toUnsignedLong(version), prevHash, merkleRoot, time, difficulty, Integer.toUnsignedLong(nonce), hash);
        }
    }

    @Override
    public long version() {
        return Integer.toUnsignedLong(version);
    }

    @Override
    public Sha256Hash prevHash() {
        return prevHash;
    }

    @Override
    public Sha256Hash merkleRoot() {
        return merkleRoot;
    }

    @Override
    public Instant time() {
        return time;
    }

    @Override
    public Difficulty difficulty() {
        return difficulty;
    }

    @Override
    public long nonce() {
        return Integer.toUnsignedLong(nonce);
    }

    @Override
    public Sha256Hash getHash() {
        return hash;
    }

    @Override
    public Sha256Hash hash() {
        return hash;
    }

    @Override
    void setMerkleRoot(Sha256Hash value) {
        throw new UnsupportedOperationException("this block is immutable");
    }

    @Override
    void setTime(Instant time) {
        throw new UnsupportedOperationException("this block is immutable");
    }

    @Override
    void setDifficultyTarget(Difficulty difficultyTarget) {
        throw new UnsupportedOperationException("this block is immutable");
    }

    @Override
    void setNonce(long nonce) {
        throw new UnsupportedOperationException("this block is immutable");
    }

    @Override
    public void addTransaction(Transaction t) {
        throw new UnsupportedOperationException("this block is immutable");
    }

    @Override
    void replaceTransactions(List<Transaction> transactions) {
        throw new UnsupportedOperationException("this block is immutable");
    }

    // This method will be removed when the refactoring is finished and only FinishedBlock.Full will implement this method.
    @Override
    public List<Transaction> transactions() {
        throw new NullPointerException("block is header-only");
    }
}
