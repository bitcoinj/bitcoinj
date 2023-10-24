/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

import com.google.common.annotations.VisibleForTesting;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.Buffers;
import org.bitcoinj.base.internal.Stopwatch;
import org.bitcoinj.base.internal.StreamUtils;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.InternalUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.params.BitcoinNetworkParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptOpCodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.IntStream;

import static org.bitcoinj.base.Coin.FIFTY_COINS;
import static org.bitcoinj.base.Sha256Hash.hashTwice;
import static org.bitcoinj.base.internal.Preconditions.check;
import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * <p>A block is a group of transactions, and is one of the fundamental data structures of the Bitcoin system.
 * It records a set of {@link Transaction}s together with some data that links it into a place in the global block
 * chain, and proves that a difficult calculation was done over its contents. See
 * <a href="http://www.bitcoin.org/bitcoin.pdf">the Bitcoin technical paper</a> for
 * more detail on blocks.</p>
 *
 * <p>To get a block, you can either build one from the raw bytes you can get from another implementation, or request one
 * specifically using {@link Peer#getBlock(Sha256Hash)}, or grab one from a downloaded {@link BlockChain}.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class Block extends BaseMessage {
    /**
     * Flags used to control which elements of block validation are done on
     * received blocks.
     */
    public enum VerifyFlag {
        /** Check that block height is in coinbase transaction (BIP 34). */
        HEIGHT_IN_COINBASE
    }

    private static final Logger log = LoggerFactory.getLogger(Block.class);

    /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte. */
    public static final int HEADER_SIZE = 80;

    static final Duration ALLOWED_TIME_DRIFT = Duration.ofHours(2); // Same value as Bitcoin Core.

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public static final int MAX_BLOCK_SIZE = 1_000_000;
    /**
     * A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on
     * the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very
     * expensive/slow to verify.
     */
    public static final int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;

    /** Standard maximum value for difficultyTarget (nBits) (Bitcoin MainNet and TestNet) */
    public static final long STANDARD_MAX_DIFFICULTY_TARGET = 0x1d00ffffL;

    /** A value for difficultyTarget (nBits) that allows (slightly less than) half of all possible hash solutions. Used in unit testing. */
    public static final long EASIEST_DIFFICULTY_TARGET = 0x207fFFFFL;

    /** Value to use if the block height is unknown */
    public static final int BLOCK_HEIGHT_UNKNOWN = -1;
    /** Height of the first block */
    public static final int BLOCK_HEIGHT_GENESIS = 0;

    public static final long BLOCK_VERSION_GENESIS = 1;
    /** Block version introduced in BIP 34: Height in coinbase */
    public static final long BLOCK_VERSION_BIP34 = 2;
    /** Block version introduced in BIP 66: Strict DER signatures */
    public static final long BLOCK_VERSION_BIP66 = 3;
    /** Block version introduced in BIP 65: OP_CHECKLOCKTIMEVERIFY */
    public static final long BLOCK_VERSION_BIP65 = 4;

    // Fields defined as part of the protocol format.
    private final long version;
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot, witnessRoot;
    private Instant time;
    private long difficultyTarget; // "nBits"
    private long nonce;

    // If null, it means this object holds only the headers.
    // For testing only
    @Nullable List<Transaction> transactions;

    /** Stores the hash of the block. If null, getHash() will recalculate it. */
    private Sha256Hash hash;

    /**
     * Deserialize this message from a given payload.
     *
     * @param payload payload to deserialize from
     * @return read message
     * @throws BufferUnderflowException if the read message extends beyond the remaining bytes of the payload
     */
    public static Block read(ByteBuffer payload) throws BufferUnderflowException, ProtocolException {
        // header
        payload.mark();
        long version = ByteUtils.readUint32(payload);
        Sha256Hash prevBlockHash = Sha256Hash.read(payload);
        Sha256Hash merkleRoot = Sha256Hash.read(payload);
        Instant time = Instant.ofEpochSecond(ByteUtils.readUint32(payload));
        long difficultyTarget = ByteUtils.readUint32(payload);
        long nonce = ByteUtils.readUint32(payload);
        payload.reset(); // read again from the mark for the hash
        Sha256Hash hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(Buffers.readBytes(payload, HEADER_SIZE)));
        // transactions
        List<Transaction> transactions = payload.hasRemaining() ? // otherwise this message is just a header
                readTransactions(payload) :
                null;
        Block block = new Block(version, prevBlockHash, merkleRoot, time, difficultyTarget, nonce, transactions);
        block.hash = hash;
        return block;
    }

    /**
     * Read transactions from a block message.
     * @param payload Contains the block message being read
     * @return An unmodifiable list of transactions
     * @throws BufferUnderflowException if end-of-buffer reached before a complete, valid message could be read
     * @throws ProtocolException if the message is not compliant with the protocol
     */
    private static List<Transaction> readTransactions(ByteBuffer payload) throws BufferUnderflowException,
            ProtocolException {
        VarInt numTransactions = VarInt.read(payload);
        check(numTransactions.fitsInt(), BufferUnderflowException::new);
        return IntStream.range(0, numTransactions.intValue())
                .mapToObj(i -> Transaction.read(payload))
                .collect(StreamUtils.toUnmodifiableList());
    }

    /** Special case constructor, used for unit tests. */
    // For testing only
    Block(long setVersion) {
        // Set up a few basic things. We are not complete after this though.
        this(setVersion,
                TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS), // convert to Bitcoin time)
                0x1d07fff8L,
                0,
                Collections.emptyList());
    }

    // For unit-test genesis blocks
    // For testing only
    Block(long setVersion, Instant time, long difficultyTarget, List<Transaction> transactions) {
        this(setVersion, time, difficultyTarget, 0, transactions);
        // Solve for nonce?
    }

    // For genesis blocks (and also unit tests)
    Block(long setVersion, Instant time, long difficultyTarget, long nonce, List<Transaction> transactions) {
        this.version = setVersion;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
        this.prevBlockHash = Sha256Hash.ZERO_HASH;
        this.transactions = new ArrayList<>(Objects.requireNonNull(transactions));
    }

    /**
     * Construct a block initialized with all the given fields.
     * @param version This should usually be set to 1 or 2, depending on if the height is in the coinbase input.
     * @param prevBlockHash Reference to previous block in the chain or {@link Sha256Hash#ZERO_HASH} if genesis.
     * @param merkleRoot The root of the merkle tree formed by the transactions.
     * @param time time when the block was mined.
     * @param difficultyTarget Number which this block hashes lower than.
     * @param nonce Arbitrary number to make the block hash lower than the target.
     * @param transactions List of transactions including the coinbase, or {@code null} for header-only blocks
     */
    public Block(long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, Instant time,
                 long difficultyTarget, long nonce, @Nullable List<Transaction> transactions) {
        super();
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
        this.transactions = transactions != null ?
                new ArrayList<>(transactions) :
                null;
    }

    /**
     * Construct a block initialized with all the given fields.
     * @param version This should usually be set to 1 or 2, depending on if the height is in the coinbase input.
     * @param prevBlockHash Reference to previous block in the chain or {@link Sha256Hash#ZERO_HASH} if genesis.
     * @param merkleRoot The root of the merkle tree formed by the transactions.
     * @param time UNIX time seconds when the block was mined.
     * @param difficultyTarget Number which this block hashes lower than.
     * @param nonce Arbitrary number to make the block hash lower than the target.
     * @param transactions List of transactions including the coinbase, or {@code null} for header-only blocks
     * @deprecated use {@link #Block(long, Sha256Hash, Sha256Hash, Instant, long, long, List)}
     */
    @Deprecated
    public Block(long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, long time,
                 long difficultyTarget, long nonce, @Nullable List<Transaction> transactions) {
        this(version, prevBlockHash, merkleRoot, Instant.ofEpochSecond(time), difficultyTarget, nonce,
                transactions);
    }

    public static Block createGenesis(Instant time, long difficultyTarget) {
        return new Block(BLOCK_VERSION_GENESIS, time, difficultyTarget, genesisTransactions());
    }

    public static Block createGenesis(Instant time, long difficultyTarget, long nonce) {
        return new Block(BLOCK_VERSION_GENESIS, time, difficultyTarget, nonce, genesisTransactions());
    }

    private static List<Transaction> genesisTransactions() {
        Transaction tx = Transaction.coinbase(genesisTxInputScriptBytes);
        tx.addOutput(new TransactionOutput(tx, FIFTY_COINS, genesisTxScriptPubKeyBytes));
        return Collections.singletonList(tx);
    }

    // A script containing the difficulty bits and the following message:
    //
    //   "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    private static final byte[] genesisTxInputScriptBytes = ByteUtils.parseHex
                ("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73");

    private static final byte[] genesisTxScriptPubKeyBytes = new ScriptBuilder()
                .data(ByteUtils.parseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"))
                .op(ScriptOpCodes.OP_CHECKSIG)
                .build()
                .program();

    @Override
    public int messageSize() {
        int size = HEADER_SIZE;
        List<Transaction> transactions = getTransactions();
        if (transactions != null) {
            size += VarInt.sizeOf(transactions.size());
            for (Transaction tx : transactions) {
                size += tx.messageSize();
            }
        }
        return size;
    }

    // default for testing
    void writeHeader(OutputStream stream) throws IOException {
        ByteUtils.writeInt32LE(version, stream);
        stream.write(prevBlockHash.serialize());
        stream.write(getMerkleRoot().serialize());
        ByteUtils.writeInt32LE(time.getEpochSecond(), stream);
        ByteUtils.writeInt32LE(difficultyTarget, stream);
        ByteUtils.writeInt32LE(nonce, stream);
    }

    private void writeTransactions(OutputStream stream) throws IOException {
        // check for no transaction conditions first
        // must be a more efficient way to do this but I'm tired atm.
        if (transactions == null) {
            return;
        }

        stream.write(VarInt.of(transactions.size()).serialize());
        for (Transaction tx : transactions) {
            tx.bitcoinSerializeToStream(stream);
        }
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        writeHeader(stream);
        writeTransactions(stream);
    }

    protected void unCache() {
        // Since we have alternate uncache methods to use internally this will only ever be called by a child
        // transaction so we only need to invalidate that part of the cache.
        unCacheTransactions();
    }

    private void unCacheHeader() {
        hash = null;
    }

    private void unCacheTransactions() {
        // Current implementation has to uncache headers as well as any change to a tx will alter the merkle root. In
        // future we can go more granular and cache merkle root separately so rest of the header does not need to be
        // rewritten.
        unCacheHeader();
        // Clear merkleRoot last as it may end up being parsed during unCacheHeader().
        merkleRoot = null;
    }

    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    private Sha256Hash calculateHash() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(HEADER_SIZE);
            writeHeader(bos);
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on
     * the block explorer. If you call this on block 1 in the mainnet chain
     * you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".
     */
    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     */
    public Sha256Hash getHash() {
        if (hash == null)
            hash = calculateHash();
        return hash;
    }

    /**
     * The number that is one greater than the largest representable SHA-256
     * hash.
     */
    private static BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);

    /**
     * Returns the work represented by this block.<p>
     *
     * Work is defined as the number of tries needed to solve a block in the
     * average case. Consider a difficulty target that covers 5% of all possible
     * hash values. Then the work of the block will be 20. As the target gets
     * lower, the amount of work goes up.
     */
    public BigInteger getWork() throws VerificationException {
        BigInteger target = getDifficultyTargetAsInteger();
        return LARGEST_HASH.divide(target.add(BigInteger.ONE));
    }

    /**
     * Returns a copy of the block, but without any transactions.
     * @return new, header-only {@code Block}
     */
    public Block cloneAsHeader() {
        Block block = new Block(version, prevBlockHash, getMerkleRoot(), time, difficultyTarget, nonce, null);
        block.hash = getHash();
        return block;
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append(" block: \n");
        s.append("   hash: ").append(getHashAsString()).append('\n');
        s.append("   version: ").append(version);
        String bips = InternalUtils.commaJoin(isBIP34() ? "BIP34" : null, isBIP66() ? "BIP66" : null, isBIP65() ? "BIP65" : null);
        if (!bips.isEmpty())
            s.append(" (").append(bips).append(')');
        s.append('\n');
        s.append("   previous block: ").append(getPrevBlockHash()).append("\n");
        s.append("   time: ").append(time).append(" (").append(TimeUtils.dateTimeFormat(time)).append(")\n");
        s.append("   difficulty target (nBits): ").append(difficultyTarget).append("\n");
        s.append("   nonce: ").append(nonce).append("\n");
        if (transactions != null && transactions.size() > 0) {
            s.append("   merkle root: ").append(getMerkleRoot()).append("\n");
            s.append("   witness root: ").append(getWitnessRoot()).append("\n");
            s.append("   with ").append(transactions.size()).append(" transaction(s):\n");
            for (Transaction tx : transactions) {
                s.append(tx).append('\n');
            }
        }
        return s.toString();
    }

    /**
     * <p>Finds a value of nonce that makes the blocks hash lower than the difficulty target. This is called mining, but
     * solve() is far too slow to do real mining with. It exists only for unit testing purposes.
     *
     * <p>This can loop forever if a solution cannot be found solely by incrementing nonce. It doesn't change
     * extraNonce.</p>
     */
    @VisibleForTesting
    public void solve() {
        Duration warningThreshold = Duration.ofSeconds(5);
        Stopwatch watch = Stopwatch.start();
        while (true) {
            try {
                // Is our proof of work valid yet?
                if (checkProofOfWork(false))
                    return;
                // No, so increment the nonce and try again.
                setNonce(getNonce() + 1);

                if (watch.isRunning() && watch.elapsed().compareTo(warningThreshold) > 0) {
                    watch.stop();
                    log.warn("trying to solve block for longer than {} seconds", warningThreshold.getSeconds());
                }
            } catch (VerificationException e) {
                throw new RuntimeException(e); // Cannot happen.
            }
        }
    }

    /**
     * Returns the difficulty target as a 256 bit value that can be compared to a SHA-256 hash. Inside a block the
     * target is represented using a compact form.
     *
     * @return difficulty target as 256-bit value
     */
    public BigInteger getDifficultyTargetAsInteger() {
        return ByteUtils.decodeCompactBits(difficultyTarget);
    }

    /** Returns true if the hash of the block is OK (lower than difficulty target). */
    protected boolean checkProofOfWork(boolean throwException) throws VerificationException {
        // shortcut for unit-testing
        if (Context.get().isRelaxProofOfWork())
            return true;

        // This part is key - it is what proves the block was as difficult to make as it claims
        // to be. Note however that in the context of this function, the block can claim to be
        // as difficult as it wants to be .... if somebody was able to take control of our network
        // connection and fork us onto a different chain, they could send us valid blocks with
        // ridiculously easy difficulty and this function would accept them.
        //
        // To prevent this attack from being possible, elsewhere we check that the difficultyTarget
        // field is of the right value. This requires us to have the preceding blocks.
        BigInteger target = getDifficultyTargetAsInteger();

        BigInteger h = getHash().toBigInteger();
        if (h.compareTo(target) > 0) {
            // Proof of work check failed!
            if (throwException)
                throw new VerificationException("Hash is higher than target: " + getHashAsString() + " vs "
                        + target.toString(16));
            else
                return false;
        }
        return true;
    }

    private void checkTimestamp() throws VerificationException {
        final Instant allowedTime = TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS).plus(ALLOWED_TIME_DRIFT);
        if (time.isAfter(allowedTime))
            throw new VerificationException(String.format(Locale.US,
                    "Block too far in future: %s (%d) vs allowed %s (%d)",
                    TimeUtils.dateTimeFormat(time), time.toEpochMilli(),
                    TimeUtils.dateTimeFormat(allowedTime), allowedTime.toEpochMilli()));
    }

    private void checkSigOps() throws VerificationException {
        // Check there aren't too many signature verifications in the block. This is an anti-DoS measure, see the
        // comments for MAX_BLOCK_SIGOPS.
        int sigOps = 0;
        for (Transaction tx : transactions) {
            sigOps += tx.getSigOpCount();
        }
        if (sigOps > MAX_BLOCK_SIGOPS)
            throw new VerificationException("Block had too many Signature Operations");
    }

    private void checkMerkleRoot() throws VerificationException {
        Sha256Hash calculatedRoot = calculateMerkleRoot();
        if (!calculatedRoot.equals(merkleRoot)) {
            log.error("Merkle tree did not verify");
            throw new VerificationException("Merkle hashes do not match: " + calculatedRoot + " vs " + merkleRoot);
        }
    }

    // For testing only
    void checkWitnessRoot() throws VerificationException {
        Transaction coinbase = transactions.get(0);
        checkState(coinbase.isCoinBase());
        Sha256Hash witnessCommitment = coinbase.findWitnessCommitment();
        if (witnessCommitment != null) {
            byte[] witnessReserved = null;
            TransactionWitness witness = coinbase.getInput(0).getWitness();
            if (witness.getPushCount() != 1)
                throw new VerificationException("Coinbase witness reserved invalid: push count");
            witnessReserved = witness.getPush(0);
            if (witnessReserved.length != 32)
                throw new VerificationException("Coinbase witness reserved invalid: length");

            Sha256Hash witnessRootHash = Sha256Hash.twiceOf(getWitnessRoot().serialize(), witnessReserved);
            if (!witnessRootHash.equals(witnessCommitment))
                throw new VerificationException("Witness merkle root invalid. Expected " + witnessCommitment.toString()
                        + " but got " + witnessRootHash.toString());
        } else {
            for (Transaction tx : transactions) {
                if (tx.hasWitnesses())
                    throw new VerificationException("Transaction witness found but no witness commitment present");
            }
        }
    }

    private Sha256Hash calculateMerkleRoot() {
        List<Sha256Hash> tree = buildMerkleTree(false);
        return tree.get(tree.size() - 1);
    }

    private Sha256Hash calculateWitnessRoot() {
        List<Sha256Hash> tree = buildMerkleTree(true);
        return tree.get(tree.size() - 1);
    }

    private List<Sha256Hash> buildMerkleTree(boolean useWTxId) {
        // The Merkle root is based on a tree of hashes calculated from the transactions:
        //
        //     root
        //      / \
        //   A      B
        //  / \    / \
        // t1 t2 t3 t4
        //
        // The tree is represented as a list: t1,t2,t3,t4,A,B,root where each
        // entry is a hash.
        //
        // The hashing algorithm is double SHA-256. The leaves are a hash of the serialized contents of the transaction.
        // The interior nodes are hashes of the concatenation of the two child hashes.
        //
        // This structure allows the creation of proof that a transaction was included into a block without having to
        // provide the full block contents. Instead, you can provide only a Merkle branch. For example to prove tx2 was
        // in a block you can just provide tx2, the hash(tx1) and B. Now the other party has everything they need to
        // derive the root, which can be checked against the block header. These proofs aren't used right now but
        // will be helpful later when we want to download partial block contents.
        //
        // Note that if the number of transactions is not even the last tx is repeated to make it so (see
        // tx3 above). A tree with 5 transactions would look like this:
        //
        //         root
        //        /     \
        //       1        5
        //     /   \     / \
        //    2     3    4  4
        //  / \   / \   / \
        // t1 t2 t3 t4 t5 t5
        ArrayList<Sha256Hash> tree = new ArrayList<>(transactions.size());
        // Start by adding all the hashes of the transactions as leaves of the tree.
        for (Transaction tx : transactions) {
            final Sha256Hash hash;
            if (useWTxId && tx.isCoinBase())
                hash = Sha256Hash.ZERO_HASH;
            else
                hash = useWTxId ? tx.getWTxId() : tx.getTxId();
            tree.add(hash);
        }
        int levelOffset = 0; // Offset in the list where the currently processed level starts.
        // Step through each level, stopping when we reach the root (levelSize == 1).
        for (int levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
            // For each pair of nodes on that level:
            for (int left = 0; left < levelSize; left += 2) {
                // The right hand node can be the same as the left hand, in the case where we don't have enough
                // transactions.
                int right = Math.min(left + 1, levelSize - 1);
                Sha256Hash leftHash = tree.get(levelOffset + left);
                Sha256Hash rightHash = tree.get(levelOffset + right);
                tree.add(Sha256Hash.wrapReversed(hashTwice(
                        leftHash.serialize(),
                        rightHash.serialize())));
            }
            // Move to the next level.
            levelOffset += levelSize;
        }
        return tree;
    }

    /**
     * Verify the transactions on a block.
     *
     * @param height block height, if known, or -1 otherwise. If provided, used
     * to validate the coinbase input script of v2 and above blocks.
     * @throws VerificationException if there was an error verifying the block.
     */
    private void checkTransactions(final int height, final EnumSet<VerifyFlag> flags)
            throws VerificationException {
        // The first transaction in a block must always be a coinbase transaction.
        if (!transactions.get(0).isCoinBase())
            throw new VerificationException("First tx is not coinbase");
        if (flags.contains(Block.VerifyFlag.HEIGHT_IN_COINBASE) && height >= BLOCK_HEIGHT_GENESIS) {
            transactions.get(0).checkCoinBaseHeight(height);
        }
        // The rest must not be.
        for (int i = 1; i < transactions.size(); i++) {
            if (transactions.get(i).isCoinBase())
                throw new VerificationException("TX " + i + " is coinbase when it should not be.");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return getHash().equals(((Block)o).getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }

    /**
     * Returns the merkle root in big endian form, calculating it from transactions if necessary.
     */
    public Sha256Hash getMerkleRoot() {
        if (merkleRoot == null) {
            //TODO check if this is really necessary.
            unCacheHeader();
            merkleRoot = calculateMerkleRoot();
        }
        return merkleRoot;
    }

    /** Exists only for unit testing. */
    // For testing only
    void setMerkleRoot(Sha256Hash value) {
        unCacheHeader();
        merkleRoot = value;
        hash = null;
    }

    /**
     * Returns the witness root in big endian form, calculating it from transactions if necessary.
     */
    public Sha256Hash getWitnessRoot() {
        if (witnessRoot == null)
            witnessRoot = calculateWitnessRoot();
        return witnessRoot;
    }

    /** Adds a transaction to this block. The nonce and merkle root are invalid after this. */
    public void addTransaction(Transaction t) {
        addTransaction(t, true);
    }

    /** Adds a transaction to this block, with or without checking the sanity of doing so */
    void addTransaction(Transaction t, boolean runSanityChecks) {
        unCacheTransactions();
        if (transactions == null) {
            transactions = new ArrayList<>();
        }
        if (runSanityChecks && transactions.size() == 0 && !t.isCoinBase())
            throw new RuntimeException("Attempted to add a non-coinbase transaction as the first transaction: " + t);
        else if (runSanityChecks && transactions.size() > 0 && t.isCoinBase())
            throw new RuntimeException("Attempted to add a coinbase transaction when there already is one: " + t);
        transactions.add(t);
        // Force a recalculation next time the values are needed.
        merkleRoot = null;
        hash = null;
    }

    /** Returns the version of the block data structure as defined by the Bitcoin protocol. */
    public long getVersion() {
        return version;
    }

    /**
     * Returns the hash of the previous block in the chain, as defined by the block header.
     */
    public Sha256Hash getPrevBlockHash() {
        return prevBlockHash;
    }

    // For testing only
    void setPrevBlockHash(Sha256Hash prevBlockHash) {
        unCacheHeader();
        this.prevBlockHash = prevBlockHash;
        this.hash = null;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node.
     */
    public Instant time() {
        return time;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node. This
     * is measured in seconds since the UNIX epoch (midnight Jan 1st 1970).
     * @deprecated use {@link #time()}
     */
    @Deprecated
    public long getTimeSeconds() {
        return time.getEpochSecond();
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node.
     * @deprecated use {@link #time()}
     */
    @Deprecated
    public Date getTime() {
        return Date.from(time());
    }

    // For testing only
    void setTime(Instant time) {
        unCacheHeader();
        this.time = time.truncatedTo(ChronoUnit.SECONDS); // convert to Bitcoin time
        this.hash = null;
    }

    /**
     * Returns the difficulty of the proof of work that this block should meet encoded <b>in compact form</b>. The {@link
     * BlockChain} verifies that this is not too easy by looking at the length of the chain when the block is added.
     * To find the actual value the hash should be compared against, use
     * {@link Block#getDifficultyTargetAsInteger()}. Note that this is <b>not</b> the same as
     * the difficulty value reported by the Bitcoin "getdifficulty" RPC that you may see on various block explorers.
     * That number is the result of applying a formula to the underlying difficulty to normalize the minimum to 1.
     * Calculating the difficulty that way is currently unsupported.
     */
    public long getDifficultyTarget() {
        return difficultyTarget;
    }

    /** Sets the difficulty target in compact form. */
    // For testing only
    void setDifficultyTarget(long compactForm) {
        unCacheHeader();
        this.difficultyTarget = compactForm;
        this.hash = null;
    }

    /**
     * Returns the nonce, an arbitrary value that exists only to make the hash of the block header fall below the
     * difficulty target.
     */
    public long getNonce() {
        return nonce;
    }

    /** Sets the nonce and clears any cached data. */
    // For testing only
    void setNonce(long nonce) {
        unCacheHeader();
        this.nonce = nonce;
        this.hash = null;
    }

    /** Returns an unmodifiable list of transactions held in this block, or null if this object represents just a header. */
    @Nullable
    public List<Transaction> getTransactions() {
        return transactions == null ? null : Collections.unmodifiableList(transactions);
    }

    // ///////////////////////////////////////////////////////////////////////////////////////////////
    // Unit testing related methods.

    // Used to make transactions unique.
    private static int txCounter;

    /** Adds a coinbase transaction to the block. This exists for unit tests.
     * 
     * @param height block height, if known, or -1 otherwise.
     */
    // For testing only
    void addCoinbaseTransaction(byte[] pubKeyTo, Coin value, final int height) {
        unCacheTransactions();
        transactions = new ArrayList<>();
        Transaction coinbase = new Transaction();
        final ScriptBuilder inputBuilder = new ScriptBuilder();

        if (height >= Block.BLOCK_HEIGHT_GENESIS) {
            inputBuilder.number(height);
        }
        inputBuilder.data(new byte[]{(byte) txCounter, (byte) (txCounter++ >> 8)});

        // A real coinbase transaction has some stuff in the scriptSig like the extraNonce and difficulty. The
        // transactions are distinguished by every TX output going to a different key.
        //
        // Here we will do things a bit differently so a new address isn't needed every time. We'll put a simple
        // counter in the scriptSig so every transaction has a different hash.
        coinbase.addInput(TransactionInput.coinbaseInput(coinbase,
                inputBuilder.build().program()));
        coinbase.addOutput(new TransactionOutput(coinbase, value,
                ScriptBuilder.createP2PKOutputScript(ECKey.fromPublicOnly(pubKeyTo)).program()));
        transactions.add(coinbase);
    }

    private static final byte[] EMPTY_BYTES = new byte[32];

    // It's pretty weak to have this around at runtime: fix later.
    private static final byte[] pubkeyForTesting = new ECKey().getPubKey();

    /**
     * Returns a solved block that builds on top of this one. This exists for unit tests.
     *
     * @param to      if not null, 50 coins are sent to the address
     * @param version version of the block to create
     * @param time    time of the block to create
     * @param height  block height if known, or -1 otherwise
     * @return created block
     */
    @VisibleForTesting
    public Block createNextBlock(@Nullable Address to, long version, Instant time, int height) {
        return createNextBlock(to, version, null, time, pubkeyForTesting, FIFTY_COINS, height);
    }

    /**
     * Returns a solved block that builds on top of this one. This exists for unit tests.
     * In this variant you can specify a public key (pubkey) for use in generating coinbase blocks.
     *
     * @param to            if not null, 50 coins are sent to the address
     * @param version       version of the block to create
     * @param prevOut       previous output to spend by the "50 coins transaction"
     * @param time          time of the block to create
     * @param pubKey        for the coinbase
     * @param coinbaseValue for the coinbase
     * @param height        block height if known, or -1 otherwise
     * @return created block
     */
    // For testing only
    Block createNextBlock(@Nullable Address to, long version, @Nullable TransactionOutPoint prevOut, Instant time,
                          byte[] pubKey, Coin coinbaseValue, int height) {
        Block b = new Block(version);
        b.setDifficultyTarget(difficultyTarget);
        b.addCoinbaseTransaction(pubKey, coinbaseValue, height);

        if (to != null) {
            // Add a transaction paying 50 coins to the "to" address.
            Transaction t = new Transaction();
            t.addOutput(new TransactionOutput(t, FIFTY_COINS, to));
            // The input does not really need to be a valid signature, as long as it has the right general form.
            TransactionInput input;
            if (prevOut == null) {
                prevOut = new TransactionOutPoint(0, nextTestOutPointHash());
            }
            input = new TransactionInput(t, Script.createInputScript(EMPTY_BYTES, EMPTY_BYTES), prevOut);
            t.addInput(input);
            b.addTransaction(t);
        }

        b.setPrevBlockHash(getHash());
        // Don't let timestamp go backwards
        Instant bitcoinTime = time.truncatedTo(ChronoUnit.SECONDS);
        if (time().compareTo(bitcoinTime) >= 0)
            b.setTime(time().plusSeconds(1));
        else
            b.setTime(bitcoinTime);
        b.solve();
        try {
            Block.verifyHeader(b);
        } catch (VerificationException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
        if (b.getVersion() != version) {
            throw new RuntimeException();
        }
        return b;
    }

    // Importantly the outpoint hash cannot be zero as that's how we detect a coinbase transaction in isolation
    // but it must be unique to avoid 'different' transactions looking the same.
    private Sha256Hash nextTestOutPointHash() {
        byte[] counter = new byte[32];
        counter[0] = (byte) txCounter;
        counter[1] = (byte) (txCounter++ >> 8);
        return Sha256Hash.wrap(counter);
    }

    /**
     * This method is intended for test use only.
     *
     * @param to      if not null, 50 coins are sent to the address
     * @param prevOut previous output to spend by the "50 coins transaction"
     * @return created block
     */
    @VisibleForTesting
    public Block createNextBlock(@Nullable Address to, TransactionOutPoint prevOut) {
        return createNextBlock(to, BLOCK_VERSION_GENESIS, prevOut, time().plusSeconds(5), pubkeyForTesting,
                FIFTY_COINS, BLOCK_HEIGHT_UNKNOWN);
    }

    /**
     * This method is intended for test use only.
     *
     * @param to            if not null, 50 coins are sent to the address
     * @param coinbaseValue for the coinbase
     * @return created block
     */
    @VisibleForTesting
    public Block createNextBlock(@Nullable Address to, Coin coinbaseValue) {
        return createNextBlock(to, BLOCK_VERSION_GENESIS, null, time().plusSeconds(5), pubkeyForTesting,
                coinbaseValue, BLOCK_HEIGHT_UNKNOWN);
    }

    /**
     * This method is intended for test use only.
     *
     * @param to if not null, 50 coins are sent to the address
     * @return created block
     */
    @VisibleForTesting
    public Block createNextBlock(@Nullable Address to) {
        return createNextBlock(to, FIFTY_COINS);
    }

    /**
     * This method is intended for test use only.
     *
     * @param version       version of the block to create
     * @param pubKey        for the coinbase
     * @param coinbaseValue for the coinbase
     * @param height        block height if known, or -1 otherwise
     * @return created block
     */
    @VisibleForTesting
    public Block createNextBlockWithCoinbase(long version, byte[] pubKey, Coin coinbaseValue, int height) {
        return createNextBlock(null, version, (TransactionOutPoint) null, TimeUtils.currentTime(), pubKey,
                coinbaseValue, height);
    }

    /**
     * Create a block sending 50BTC as a coinbase transaction to the public key specified.
     * This method is intended for test use only.
     *
     * @param version version of the block to create
     * @param pubKey  for the coinbase
     * @param height  block height if known, or -1 otherwise
     * @return created block
     */
    // For testing only
    Block createNextBlockWithCoinbase(long version, byte[] pubKey, int height) {
        return createNextBlock(null, version, (TransactionOutPoint) null, TimeUtils.currentTime(), pubKey,
                FIFTY_COINS, height);
    }

    /**
     * Return whether this block contains any transactions.
     * 
     * @return  true if the block contains transactions, false otherwise (is
     * purely a header).
     */
    public boolean hasTransactions() {
        return (this.transactions != null) && !this.transactions.isEmpty();
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki">BIP34: Height in Coinbase</a>.
     */
    public boolean isBIP34() {
        return version >= BLOCK_VERSION_BIP34;
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki">BIP66: Strict DER signatures</a>.
     */
    public boolean isBIP66() {
        return version >= BLOCK_VERSION_BIP66;
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki">BIP65: OP_CHECKLOCKTIMEVERIFY</a>.
     */
    public boolean isBIP65() {
        return version >= BLOCK_VERSION_BIP65;
    }

    /**
     * Verifies both the header and that the transactions hash to the merkle root.
     *
     * @param params parameters for the verification rules
     * @param block  block to verify
     * @param height block height, if known, or -1 otherwise.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if at least one of the rules is violated
     */
    public static void verify(NetworkParameters params, Block block, int height, EnumSet<VerifyFlag> flags) throws VerificationException {
        verifyHeader(block);
        verifyTransactions(params, block, height, flags);
    }

    /**
     * Checks the block data to ensure it follows the rules laid out in the network parameters. Specifically,
     * throws an exception if the proof of work is invalid, or if the timestamp is too far from what it should be.
     * This is <b>not</b> everything that is required for a block to be valid, only what is checkable independent
     * of the chain and without a transaction index.
     *
     * @param block  block to verify
     * @throws VerificationException if at least one of the rules is violated
     */
    public static void verifyHeader(Block block) throws VerificationException {
        // Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
        // network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
        //
        // Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
        // enough, it's probably been done by the network.
        block.checkProofOfWork(true);
        block.checkTimestamp();
    }

    /**
     * Checks the block contents
     *
     * @param params parameters for the verification rules
     * @param block  block to verify
     * @param height block height, if known, or -1 otherwise. If valid, used
     * to validate the coinbase input script of v2 and above blocks.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if at least one of the rules is violated
     */
    public static void verifyTransactions(NetworkParameters params, Block block, int height,
                                          EnumSet<VerifyFlag> flags) throws VerificationException {
        // Now we need to check that the body of the block actually matches the headers. The network won't generate
        // an invalid block, but if we didn't validate this then an untrusted man-in-the-middle could obtain the next
        // valid block from the network and simply replace the transactions in it with their own fictional
        // transactions that reference spent or non-existent inputs.
        if (block.transactions.isEmpty())
            throw new VerificationException("Block had no transactions");
        if (block.messageSize() > MAX_BLOCK_SIZE)
            throw new VerificationException("Block larger than MAX_BLOCK_SIZE");
        block.checkTransactions(height, flags);
        block.checkMerkleRoot();
        block.checkSigOps();
        for (Transaction tx : block.transactions)
            Transaction.verify(params.network(), tx);
    }
}
