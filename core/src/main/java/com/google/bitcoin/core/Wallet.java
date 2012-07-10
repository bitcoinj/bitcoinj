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

package com.google.bitcoin.core;

import com.google.bitcoin.core.WalletTransaction.Pool;
import com.google.bitcoin.store.WalletProtobufSerializer;
import com.google.bitcoin.utils.EventListenerInvoker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ExecutionException;

import static com.google.bitcoin.core.Utils.bitcoinValueToFriendlyString;
import static com.google.common.base.Preconditions.*;

/**
 * A Wallet stores keys and a record of transactions that have not yet been spent. Thus, it is capable of
 * providing transactions on demand that meet a given combined value.<p>
 * <p/>
 * The Wallet is read and written from disk, so be sure to follow the Java serialization versioning rules here. We
 * use the built in Java serialization to avoid the need to pull in a potentially large (code-size) third party
 * serialization library.<p>
 */
public class Wallet implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(Wallet.class);
    private static final long serialVersionUID = 2L;

    // Algorithm for movement of transactions between pools. Outbound tx = us spending coins. Inbound tx = us
    // receiving coins. If a tx is both inbound and outbound (spend with change) it is considered outbound for the
    // purposes of the explanation below.
    //
    // 1. Outbound tx is created by us: ->pending
    // 2. Outbound tx that was broadcast is accepted into the main chain:
    //     <-pending  and
    //       If there is a change output  ->unspent
    //       If there is no change output ->spent
    // 3. Outbound tx that was broadcast is accepted into a side chain:
    //     ->inactive  (remains in pending).
    // 4. Inbound tx is accepted into the best chain:
    //     ->unspent/spent
    // 5. Inbound tx is accepted into a side chain:
    //     ->inactive
    //     Whilst it's also 'pending' in some sense, in that miners will probably try and incorporate it into the
    //     best chain, we don't mark it as such here. It'll eventually show up after a re-org.
    // 6. Outbound tx that is pending shares inputs with a tx that appears in the main chain:
    //     <-pending ->dead
    //
    // Re-orgs:
    // 1. Tx is present in old chain and not present in new chain
    //       <-unspent/spent  ->pending
    //       These newly inactive transactions will (if they are relevant to us) eventually come back via receive()
    //       as miners resurrect them and re-include into the new best chain.
    // 2. Tx is not present in old chain and is present in new chain
    //       <-inactive  and  ->unspent/spent
    // 3. Tx is present in new chain and shares inputs with a pending transaction, including those that were resurrected
    //    due to point (1)
    //       <-pending ->dead
    //
    // Balance:
    // 1. Sum up all unspent outputs of the transactions in unspent.
    // 2. Subtract the inputs of transactions in pending.
    // 3. If requested, re-add the outputs of pending transactions that are mine. This is the estimated balance.

    /**
     * Map of txhash->Transactions that have not made it into the best chain yet. They are eligible to move there but
     * are waiting for a miner to create a block on the best chain including them. These transactions inputs count as
     * spent for the purposes of calculating our balance but their outputs are not available for spending yet. This
     * means after a spend, our balance can actually go down temporarily before going up again! We should fix this to
     * allow spending of pending transactions.
     *
     * Pending transactions get announced to peers when they first connect. This means that if we're currently offline,
     * we can still create spends and upload them to the network later.
     */
    final Map<Sha256Hash, Transaction> pending;

    /**
     * Map of txhash->Transactions where the Transaction has unspent outputs. These are transactions we can use
     * to pay other people and so count towards our balance. Transactions only appear in this map if they are part
     * of the best chain. Transactions we have broacast that are not confirmed yet appear in pending even though they
     * may have unspent "change" outputs.<p>
     * <p/>
     * Note: for now we will not allow spends of transactions that did not make it into the block chain. The code
     * that handles this in BitCoin C++ is complicated. Satoshis code will not allow you to spend unconfirmed coins,
     * however, it does seem to support dependency resolution entirely within the context of the memory pool so
     * theoretically you could spend zero-conf coins and all of them would be included together. To simplify we'll
     * make people wait but it would be a good improvement to resolve this in future.
     */
    final Map<Sha256Hash, Transaction> unspent;

    /**
     * Map of txhash->Transactions where the Transactions outputs are all fully spent. They are kept separately so
     * the time to create a spend does not grow infinitely as wallets become more used. Some of these transactions
     * may not have appeared in a block yet if they were created by us to spend coins and that spend is still being
     * worked on by miners.<p>
     * <p/>
     * Transactions only appear in this map if they are part of the best chain.
     */
    final Map<Sha256Hash, Transaction> spent;

    /**
     * An inactive transaction is one that is seen only in a block that is not a part of the best chain. We keep it
     * around in case a re-org promotes a different chain to be the best. In this case some (not necessarily all)
     * inactive transactions will be moved out to unspent and spent, and some might be moved in.<p>
     * <p/>
     * Note that in the case where a transaction appears in both the best chain and a side chain as well, it is not
     * placed in this map. It's an error for a transaction to be in both the inactive pool and unspent/spent.
     */
    private Map<Sha256Hash, Transaction> inactive;

    /**
     * A dead transaction is one that's been overridden by a double spend. Such a transaction is pending except it
     * will never confirm and so should be presented to the user in some unique way - flashing red for example. This
     * should nearly never happen in normal usage. Dead transactions can be "resurrected" by re-orgs just like any
     * other. Dead transactions are not in the pending pool.
     */
    private Map<Sha256Hash, Transaction> dead;

    /**
     * A list of public/private EC keys owned by this user.
     */
    public final ArrayList<ECKey> keychain;

    private final NetworkParameters params;

    // Primitive kind of versioning protocol that does not break serializability. If this is true it means the
    // Transaction objects in this wallet have confidence objects. If false (the default for old wallets missing
    // this field) then we need to migrate.
    private boolean hasTransactionConfidences;

    /**
     * The hash of the last block seen on the best chain
     */
    private Sha256Hash lastBlockSeenHash;

    transient private ArrayList<WalletEventListener> eventListeners;

    /**
     * Creates a new, empty wallet with no keys and no transactions. If you want to restore a wallet from disk instead,
     * see loadFromFile.
     */
    public Wallet(NetworkParameters params) {
        this.params = params;
        keychain = new ArrayList<ECKey>();
        unspent = new HashMap<Sha256Hash, Transaction>();
        spent = new HashMap<Sha256Hash, Transaction>();
        inactive = new HashMap<Sha256Hash, Transaction>();
        pending = new HashMap<Sha256Hash, Transaction>();
        dead = new HashMap<Sha256Hash, Transaction>();
        eventListeners = new ArrayList<WalletEventListener>();
        hasTransactionConfidences = true;
    }
    
    public NetworkParameters getNetworkParameters() {
        return params;
    }

    /**
     * Returns a snapshot of the keychain. This view is not live.
     */
    public synchronized Iterable<ECKey> getKeys() {
        return new ArrayList<ECKey>(keychain);
    }

    /**
     * Uses protobuf serialization to save the wallet to the given file. To learn more about this file format, see
     * {@link WalletProtobufSerializer}. Writes out first to a temporary file in the same directory and then renames
     * once written.
     */
    public synchronized void saveToFile(File f) throws IOException {
        FileOutputStream stream = null;
        File temp;
        try {
            File directory = f.getAbsoluteFile().getParentFile();
            temp = File.createTempFile("wallet", null, directory);
            stream = new FileOutputStream(temp);
            saveToFileStream(stream);
            // Attempt to force the bits to hit the disk. In reality the OS or hard disk itself may still decide
            // to not write through to physical media for at least a few seconds, but this is the best we can do.
            stream.flush();
            stream.getFD().sync();
            stream.close();
            stream = null;
            if (!temp.renameTo(f)) {
                // Work around an issue on Windows whereby you can't rename over existing files.
                if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                    if (f.delete() && temp.renameTo(f)) return;  // else fall through.
                }
                throw new IOException("Failed to rename " + temp + " to " + f);
            }
        } finally {
            if (stream != null) {
                stream.close();
            }
        }
    }

    /**
     * Uses protobuf serialization to save the wallet to the given file stream. To learn more about this file format, see
     * {@link WalletProtobufSerializer}.
     */
    public synchronized void saveToFileStream(OutputStream f) throws IOException {
        WalletProtobufSerializer.writeWallet(this, f);
    }

    /** Returns the parameters this wallet was created with. */
    public NetworkParameters getParams() {
        return params;
    }


    /**
     * Returns a wallet deserialized from the given file.
     */
    public static Wallet loadFromFile(File f) throws IOException {
        FileInputStream stream = new FileInputStream(f);
        try {
            return loadFromFileStream(stream);
        } finally {
            stream.close();
        }
    }
    
    public boolean isConsistent() {
        boolean success = true;
        // Pending and inactive can overlap, so merge them before counting
        HashSet<Transaction> pendingInactive = new HashSet<Transaction>();
        pendingInactive.addAll(pending.values());
        pendingInactive.addAll(inactive.values());
        
        Set<Transaction> transactions = getTransactions(true, true);
        
        Set<Sha256Hash> hashes = new HashSet<Sha256Hash>();
        for (Transaction tx : transactions) {
            hashes.add(tx.getHash());
        }
        
        int size1 = transactions.size();
        
        if (size1 != hashes.size()) {
            log.error("Two transactions with same hash");
            success = false;
        }
        
        int size2 = unspent.size() + spent.size() + pendingInactive.size() + dead.size();
        if (size1 != size2) {
            log.error("Inconsistent wallet sizes: {} {}", size1, size2);
            success = false;
        }
        
        for (Transaction tx : unspent.values()) {
            if (!tx.isConsistent(this, false)) {
                success = false;
                log.error("Inconsistent unspent tx {}", tx.getHashAsString());
            }
        }
        
        for (Transaction tx : spent.values()) {
            if (!tx.isConsistent(this, true)) {
                success = false;
                log.error("Inconsistent spent tx {}", tx.getHashAsString());
            }
        }
        
        return success;
    }

    /**
     * Returns a wallet deserialized from the given input stream.
     */
    public static Wallet loadFromFileStream(InputStream stream) throws IOException {
        // Determine what kind of wallet stream this is: Java Serialization or protobuf format.
        stream = new BufferedInputStream(stream);
        stream.mark(100);
        boolean serialization = stream.read() == 0xac && stream.read() == 0xed;
        stream.reset();

        Wallet wallet;
        
        if (serialization) {
            ObjectInputStream ois = null;
            try {
                ois = new ObjectInputStream(stream);
                wallet = (Wallet) ois.readObject();
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            } finally {
                if (ois != null) ois.close();
            }
        } else {
            wallet = WalletProtobufSerializer.readWallet(stream);
        }
        
        if (!wallet.isConsistent()) {
            log.error("Loaded an inconsistent wallet");
        }
        return wallet;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        eventListeners = new ArrayList<WalletEventListener>();
        maybeMigrateToTransactionConfidences();
    }

    /** Migrate old wallets that don't have any tx confidences, filling out whatever information we can. */
    private void maybeMigrateToTransactionConfidences() {
        if (hasTransactionConfidences) return;
        // We can't fill out tx confidence objects exactly, we don't have enough data to do that. But we do the
        // best we can.
        List<Transaction> transactions = new LinkedList<Transaction>();
        transactions.addAll(unspent.values());
        transactions.addAll(spent.values());
        for (Transaction tx : transactions) {
            TransactionConfidence confidence = tx.getConfidence();
            confidence.setConfidenceType(TransactionConfidence.ConfidenceType.BUILDING);
            Set<StoredBlock> appearsIn = tx.appearsIn;
            // appearsIn is being migrated away from, in favor of just storing the hashes instead of full blocks.
            // TODO: Clear this code out once old wallets fade away.
            if (appearsIn != null) {
                int minHeight = Integer.MAX_VALUE;
                for (StoredBlock block : appearsIn) {
                    minHeight = Math.min(minHeight, block.getHeight());
                }
                confidence.setAppearedAtChainHeight(minHeight);
            }
        }
        for (Transaction tx : pending.values()) {
            tx.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.NOT_SEEN_IN_CHAIN);
        }
        for (Transaction tx : inactive.values()) {
            tx.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.NOT_IN_BEST_CHAIN);
        }
        for (Transaction tx : dead.values()) {
            tx.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.OVERRIDDEN_BY_DOUBLE_SPEND);
            // We'd ideally like to set overridingTransaction here, but old wallets don't have that data.
            // Dead transactions in the wallet should be rare, so API users will just have to handle this
            // edge case until old wallets have gone away.
        }
        hasTransactionConfidences = true;
    }

    /**
     * Called by the {@link BlockChain} when we receive a new block that sends coins to one of our addresses or
     * spends coins from one of our addresses (note that a single transaction can do both).<p>
     *
     * This is necessary for the internal book-keeping Wallet does. When a transaction is received that sends us
     * coins it is added to a pool so we can use it later to create spends. When a transaction is received that
     * consumes outputs they are marked as spent so they won't be used in future.<p>
     *
     * A transaction that spends our own coins can be received either because a spend we created was accepted by the
     * network and thus made it into a block, or because our keys are being shared between multiple instances and
     * some other node spent the coins instead. We still have to know about that to avoid accidentally trying to
     * double spend.<p>
     *
     * A transaction may be received multiple times if is included into blocks in parallel chains. The blockType
     * parameter describes whether the containing block is on the main/best chain or whether it's on a presently
     * inactive side chain. We must still record these transactions and the blocks they appear in because a future
     * block might change which chain is best causing a reorganize. A re-org can totally change our balance!
     */
    public synchronized void receiveFromBlock(Transaction tx, StoredBlock block,
                                       BlockChain.NewBlockType blockType) throws VerificationException, ScriptException {
        receive(tx, block, blockType, false);
    }

    /**
     * Called when we have found a transaction (via network broadcast or otherwise) that is relevant to this wallet
     * and want to record it. Note that we <b>cannot verify these transactions at all</b>, they may spend fictional
     * coins or be otherwise invalid. They are useful to inform the user about coins they can expect to receive soon,
     * and if you trust the sender of the transaction you can choose to assume they are in fact valid and will not
     * be double spent as an optimization.
     *
     * @param tx
     * @throws VerificationException
     * @throws ScriptException
     */
    public synchronized void receivePending(Transaction tx) throws VerificationException, ScriptException {
        // Can run in a peer thread.

        // Ignore it if we already know about this transaction. Receiving a pending transaction never moves it
        // between pools.
        EnumSet<Pool> containingPools = getContainingPools(tx);
        if (!containingPools.equals(EnumSet.noneOf(Pool.class))) {
            log.info("Received tx we already saw in a block or created ourselves: " + tx.getHashAsString());
            return;
        }

        // We only care about transactions that:
        //   - Send us coins
        //   - Spend our coins
        if (!isTransactionRelevant(tx, true)) {
            log.debug("Received tx that isn't relevant to this wallet, discarding.");
            return;
        }

        BigInteger valueSentToMe = tx.getValueSentToMe(this);
        BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
        if (log.isInfoEnabled()) {
            log.info(String.format("Received a pending transaction %s that spends %s BTC from our own wallet," +
                    " and sends us %s BTC", tx.getHashAsString(), Utils.bitcoinValueToFriendlyString(valueSentFromMe),
                    Utils.bitcoinValueToFriendlyString(valueSentToMe)));
        }

        // Mark the tx as having been seen but is not yet in the chain. This will normally have been done already by
        // the Peer before we got to this point, but in some cases (unit tests, other sources of transactions) it may
        // have been missed out.
        TransactionConfidence.ConfidenceType currentConfidence = tx.getConfidence().getConfidenceType();
        if (currentConfidence == TransactionConfidence.ConfidenceType.UNKNOWN) {
            tx.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.NOT_SEEN_IN_CHAIN);
            invokeOnTransactionConfidenceChanged(tx);
        }

        // If this tx spends any of our unspent outputs, mark them as spent now, then add to the pending pool. This
        // ensures that if some other client that has our keys broadcasts a spend we stay in sync. Also updates the
        // timestamp on the transaction and runs event listeners.
        //
        // Note that after we return from this function, the wallet may have been modified.
        commitTx(tx);
    }

    // Boilerplate that allows event listeners to delete themselves during execution, and auto locks the listener.
    private void invokeOnCoinsReceived(final Transaction tx, final BigInteger balance, final BigInteger newBalance) {
        EventListenerInvoker.invoke(eventListeners, new EventListenerInvoker<WalletEventListener>() {
            @Override public void invoke(WalletEventListener listener) {
                listener.onCoinsReceived(Wallet.this, tx, balance, newBalance);
            }
        });
    }

    private void invokeOnCoinsSent(final Transaction tx, final BigInteger prevBalance, final BigInteger newBalance) {
        EventListenerInvoker.invoke(eventListeners, new EventListenerInvoker<WalletEventListener>() {
            @Override public void invoke(WalletEventListener listener) {
                listener.onCoinsSent(Wallet.this, tx, prevBalance, newBalance);
            }
        });
    }

    /**
     * Returns true if the given transaction sends coins to any of our keys, or has inputs spending any of our outputs,
     * and if includeDoubleSpending is true, also returns true if tx has inputs that are spending outputs which are
     * not ours but which are spent by pending transactions.<p>
     *
     * Note that if the tx has inputs containing one of our keys, but the connected transaction is not in the wallet,
     * it will not be considered relevant.
     */
    public synchronized boolean isTransactionRelevant(Transaction tx,
                                                      boolean includeDoubleSpending) throws ScriptException {
        return tx.getValueSentFromMe(this).compareTo(BigInteger.ZERO) > 0 ||
               tx.getValueSentToMe(this).compareTo(BigInteger.ZERO) > 0 ||
               (includeDoubleSpending && (findDoubleSpendAgainstPending(tx) != null));
    }

    /**
     * Checks if "tx" is spending any inputs of pending transactions. Not a general check, but it can work even if
     * the double spent inputs are not ours. Returns the pending tx that was double spent or null if none found.
     */
    private Transaction findDoubleSpendAgainstPending(Transaction tx) {
        // Compile a set of outpoints that are spent by tx.
        HashSet<TransactionOutPoint> outpoints = new HashSet<TransactionOutPoint>();
        for (TransactionInput input : tx.getInputs()) {
            outpoints.add(input.getOutpoint());
        }
        // Now for each pending transaction, see if it shares any outpoints with this tx.
        for (Transaction p : pending.values()) {
            for (TransactionInput input : p.getInputs()) {
                if (outpoints.contains(input.getOutpoint())) {
                    // It does, it's a double spend against the pending pool, which makes it relevant.
                    return p;
                }
            }
        }
        return null;
    }

    private synchronized void receive(Transaction tx, StoredBlock block,
                                      BlockChain.NewBlockType blockType,
                                      boolean reorg) throws VerificationException, ScriptException {
        // Runs in a peer thread.
        BigInteger prevBalance = getBalance();

        Sha256Hash txHash = tx.getHash();

        boolean bestChain = blockType == BlockChain.NewBlockType.BEST_CHAIN;
        boolean sideChain = blockType == BlockChain.NewBlockType.SIDE_CHAIN;

        BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
        BigInteger valueSentToMe = tx.getValueSentToMe(this);
        BigInteger valueDifference = valueSentToMe.subtract(valueSentFromMe);

        if (!reorg) {
            log.info("Received tx {} for {} BTC: {}", new Object[]{sideChain ? "on a side chain" : "",
                    bitcoinValueToFriendlyString(valueDifference), tx.getHashAsString()});
        }

        // If this transaction is already in the wallet we may need to move it into a different pool. At the very
        // least we need to ensure we're manipulating the canonical object rather than a duplicate.
        Transaction wtx;
        if ((wtx = pending.remove(txHash)) != null) {
            // Make sure "tx" is always the canonical object we want to manipulate, send to event handlers, etc.
            tx = wtx;

            log.info("  <-pending");
            // A transaction we created appeared in a block. Probably this is a spend we broadcast that has been
            // accepted by the network.
            if (bestChain) {
                if (valueSentToMe.equals(BigInteger.ZERO)) {
                    // There were no change transactions so this tx is fully spent.
                    log.info("  ->spent");
                    boolean alreadyPresent = spent.put(tx.getHash(), tx) != null;
                    checkState(!alreadyPresent, "TX in both pending and spent pools");
                } else {
                    // There was change back to us, or this tx was purely a spend back to ourselves (perhaps for
                    // anonymization purposes).
                    log.info("  ->unspent");
                    boolean alreadyPresent = unspent.put(tx.getHash(), tx) != null;
                    checkState(!alreadyPresent, "TX in both pending and unspent pools");
                }
            } else if (sideChain) {
                // The transaction was accepted on an inactive side chain, but not yet by the best chain.
                log.info("  ->inactive");
                // It's OK for this to already be in the inactive pool because there can be multiple independent side
                // chains in which it appears:
                //
                //     b1 --> b2
                //        \-> b3
                //        \-> b4 (at this point it's already present in 'inactive'
                boolean alreadyPresent = inactive.put(tx.getHash(), tx) != null;
                if (alreadyPresent)
                    log.info("Saw a transaction be incorporated into multiple independent side chains");
                // Put it back into the pending pool, because 'pending' means 'waiting to be included in best chain'.
                pending.put(tx.getHash(), tx);
            }
        } else {
            // This TX didn't originate with us. It could be sending us coins and also spending our own coins if keys
            // are being shared between different wallets.
            if (sideChain) {
                if (unspent.containsKey(tx.getHash()) || spent.containsKey(tx.getHash())) {
                    // This side chain block contains transactions that already appeared in the best chain. It's normal,
                    // we don't need to consider this transaction inactive, we can just ignore it.
                } else {
                    log.info("  ->inactive");
                    inactive.put(tx.getHash(), tx);
                }
            } else if (bestChain) {
                // This can trigger tx confidence listeners to be run in the case of double spends. We may need to
                // delay the execution of the listeners until the bottom to avoid the wallet mutating during updates.
                processTxFromBestChain(tx);
            }
        }

        log.info("Balance is now: " + bitcoinValueToFriendlyString(getBalance()));

        // Store the block hash
        if (bestChain) {
            if (block != null && block.getHeader() != null) {
                // Check to see if this block has been seen before
                Sha256Hash newBlockHash = block.getHeader().getHash();
                if (!newBlockHash.equals(getLastBlockSeenHash())) {
                    // new hash
                    setLastBlockSeenHash(newBlockHash);
                }
            }
        }

        // WARNING: The code beyond this point can trigger event listeners on transaction confidence objects, which are
        // in turn allowed to re-enter the Wallet. This means we cannot assume anything about the state of the wallet
        // from now on. The balance just received may already be spent.

        // Mark the tx as appearing in this block so we can find it later after a re-org. This also lets the
        // transaction update its confidence and timestamp bookkeeping data.
        if (block != null) {
            tx.setBlockAppearance(block, bestChain);
            invokeOnTransactionConfidenceChanged(tx);
        }

        // Inform anyone interested that we have received or sent coins but only if:
        //  - This is not due to a re-org.
        //  - The coins appeared on the best chain.
        //  - We did in fact receive some new money.
        //  - We have not already informed the user about the coins when we received the tx broadcast, or for our
        //    own spends. If users want to know when a broadcast tx becomes confirmed, they need to use tx confidence
        //    listeners.
        //
        // TODO: Decide whether to run the event listeners, if a tx confidence listener already modified the wallet.
        boolean wasPending = wtx != null;
        if (!reorg && bestChain && !wasPending) {
            BigInteger newBalance = getBalance();
            int diff = valueDifference.compareTo(BigInteger.ZERO);
            // We pick one callback based on the value difference, though a tx can of course both send and receive
            // coins from the wallet.
            if (diff > 0) {
                invokeOnCoinsReceived(tx, prevBalance, newBalance);
            } else if (diff == 0) {
                // Hack. Invoke onCoinsSent in order to let the client save the wallet. This needs to go away.
                invokeOnCoinsSent(tx, prevBalance, newBalance);
            } else {
                invokeOnCoinsSent(tx, prevBalance, newBalance);
            }
        }
        
        checkState(isConsistent());
    }

    /**
     * Handle when a transaction becomes newly active on the best chain, either due to receiving a new block or a
     * re-org making inactive transactions active.
     */
    private void processTxFromBestChain(Transaction tx) throws VerificationException, ScriptException {
        // This TX may spend our existing outputs even though it was not pending. This can happen in unit
        // tests, if keys are moved between wallets, and if we're catching up to the chain given only a set of keys.

        if (inactive.containsKey(tx.getHash())) {
            // This transaction was seen first on a side chain, but now it's also been seen in the best chain.
            // So we don't need to track it as inactive anymore.
            log.info("  new tx {} <-inactive", tx.getHashAsString());
            inactive.remove(tx.getHash());
        }

        updateForSpends(tx, true);
        if (!tx.getValueSentToMe(this).equals(BigInteger.ZERO)) {
            // It's sending us coins.
            log.info("  new tx ->unspent");
            boolean alreadyPresent = unspent.put(tx.getHash(), tx) != null;
            checkState(!alreadyPresent, "TX was received twice");
        } else if (!tx.getValueSentFromMe(this).equals(BigInteger.ZERO)) {
            // It spent some of our coins and did not send us any.
            log.info("  new tx ->spent");
            boolean alreadyPresent = spent.put(tx.getHash(), tx) != null;
            checkState(!alreadyPresent, "TX was received twice");
        } else {
            // It didn't send us coins nor spend any of our coins. If we're processing it, that must be because it
            // spends outpoints that are also spent by some pending transactions - maybe a double spend of somebody
            // elses coins that were originally sent to us? ie, this might be a Finney attack where we think we
            // received some money and then the sender co-operated with a miner to take back the coins, using a tx
            // that isn't involving our keys at all.
            Transaction doubleSpend = findDoubleSpendAgainstPending(tx);
            if (doubleSpend == null)
                throw new IllegalStateException("Received an irrelevant tx that was not a double spend.");
            // This is mostly the same as the codepath in updateForSpends, but that one is only triggered when
            // the transaction being double spent is actually in our wallet (ie, maybe we're double spending).
            log.warn("Saw double spend from chain override pending tx {}", doubleSpend.getHashAsString());
            log.warn("  <-pending ->dead");
            pending.remove(doubleSpend.getHash());
            dead.put(doubleSpend.getHash(), doubleSpend);
            // Inform the event listeners of the newly dead tx.
            doubleSpend.getConfidence().setOverridingTransaction(tx);
            invokeOnTransactionConfidenceChanged(doubleSpend);
        }
    }

    /**
     * Updates the wallet by checking if this TX spends any of our outputs, and marking them as spent if so. It can
     * be called in two contexts. One is when we receive a transaction on the best chain but it wasn't pending, this
     * most commonly happens when we have a set of keys but the wallet transactions were wiped and we are catching up
     * with the block chain. It can also happen if a block includes a transaction we never saw at broadcast time.
     * If this tx double spends, it takes precedence over our pending transactions and the pending tx goes dead.
     *
     * The other context it can be called is from {@link Wallet#receivePending(Transaction)} ie we saw a tx be
     * broadcast or one was submitted directly that spends our own coins. If this tx double spends it does NOT take
     * precedence because the winner will be resolved by the miners - we assume that our version will win,
     * if we are wrong then when a block appears the tx will go dead.
     */
    private void updateForSpends(Transaction tx, boolean fromChain) throws VerificationException {
        // tx is on the best chain by this point.
        List<TransactionInput> inputs = tx.getInputs();
        for (int i = 0; i < inputs.size(); i++) {
            TransactionInput input = inputs.get(i);
            TransactionInput.ConnectionResult result = input.connect(unspent, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
            if (result == TransactionInput.ConnectionResult.NO_SUCH_TX) {
                // Not found in the unspent map. Try again with the spent map.
                result = input.connect(spent, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
                if (result == TransactionInput.ConnectionResult.NO_SUCH_TX) {
                    // Doesn't spend any of our outputs or is coinbase.
                    continue;
                }
            }

            if (result == TransactionInput.ConnectionResult.ALREADY_SPENT) {
                // Double spend! Work backwards like so:
                //
                //   A  -> spent by B [pending]
                //     \-> spent by C [chain]
                Transaction doubleSpent = input.getOutpoint().fromTx;   // == A
                checkNotNull(doubleSpent);
                int index = (int) input.getOutpoint().getIndex();
                TransactionOutput output = doubleSpent.getOutputs().get(index);
                TransactionInput spentBy = checkNotNull(output.getSpentBy());
                Transaction connected = checkNotNull(spentBy.getParentTransaction());
                if (fromChain) {
                    // This must have overridden a pending tx, or the block is bad (contains transactions
                    // that illegally double spend: should never occur if we are connected to an honest node).
                    if (pending.containsKey(connected.getHash())) {
                        log.warn("Saw double spend from chain override pending tx {}", connected.getHashAsString());
                        log.warn("  <-pending ->dead");
                        pending.remove(connected.getHash());
                        dead.put(connected.getHash(), connected);
                        // Now forcibly change the connection.
                        input.connect(unspent, TransactionInput.ConnectMode.DISCONNECT_ON_CONFLICT);
                        // Inform the [tx] event listeners of the newly dead tx. This sets confidence type also.
                        connected.getConfidence().setOverridingTransaction(tx);
                        invokeOnTransactionConfidenceChanged(connected);
                    }
                } else {
                    // A pending transaction that tried to double spend our coins - we log and ignore it, because either
                    // 1) The double-spent tx is confirmed and thus this tx has no effect .... or
                    // 2) Both txns are pending, neither has priority. Miners will decide in a few minutes which won.
                    log.warn("Saw double spend from another pending transaction, ignoring tx {}",
                             tx.getHashAsString());
                    log.warn("  offending input is input {}", i);
                    return;
                }
            } else if (result == TransactionInput.ConnectionResult.SUCCESS) {
                // Otherwise we saw a transaction spend our coins, but we didn't try and spend them ourselves yet.
                // The outputs are already marked as spent by the connect call above, so check if there are any more for
                // us to use. Move if not.
                Transaction connected = checkNotNull(input.getOutpoint().fromTx);
                maybeMoveTxToSpent(connected, "prevtx");
            }
        }
    }

    /**
     * If the transactions outputs are all marked as spent, and it's in the unspent map, move it.
     */
    private void maybeMoveTxToSpent(Transaction tx, String context) {
        if (tx.isEveryOwnedOutputSpent(this)) {
            // There's nothing left I can spend in this transaction.
            if (unspent.remove(tx.getHash()) != null) {
                if (log.isInfoEnabled()) {
                    log.info("  {} {} <-unspent", tx.getHashAsString(), context);
                    log.info("  {} {} ->spent", tx.getHashAsString(), context);
                }
                spent.put(tx.getHash(), tx);
            }
        }
    }

    /**
     * Adds an event listener object. Methods on this object are called when something interesting happens,
     * like receiving money.<p>
     * <p/>
     * Threading: Event listener methods are dispatched on library provided threads and the both the wallet and the
     * listener objects are locked during dispatch, so your listeners do not have to be thread safe. However they
     * should not block as the Peer will be unresponsive to network traffic whilst your listener is running.
     */
    public synchronized void addEventListener(WalletEventListener listener) {
        eventListeners.add(listener);
    }

    /**
     * Removes the given event listener object. Returns true if the listener was removed,
     * false if that listener was never added.
     */
    public synchronized boolean removeEventListener(WalletEventListener listener) {
        return eventListeners.remove(listener);
    }

    /**
     * Updates the wallet with the given transaction: puts it into the pending pool, sets the spent flags and runs
     * the onCoinsSent/onCoinsReceived event listener. Used in two situations:<p>
     *
     * <ol>
     *     <li>When we have just successfully transmitted the tx we created to the network.</li>
     *     <li>When we receive a pending transaction that didn't appear in the chain yet, and we did not create it.</li>
     * </ol>
     */
    public synchronized void commitTx(Transaction tx) throws VerificationException {
        checkArgument(!pending.containsKey(tx.getHash()), "commitTx called on the same transaction twice");
        log.info("commitTx of {}", tx.getHashAsString());
        BigInteger balance = getBalance();
        tx.updatedAt = Utils.now();
        // Mark the outputs we're spending as spent so we won't try and use them in future creations. This will also
        // move any transactions that are now fully spent to the spent map so we can skip them when creating future
        // spends.
        updateForSpends(tx, false);
        // Add to the pending pool. It'll be moved out once we receive this transaction on the best chain.
        log.info("->pending: {}", tx.getHashAsString());
        pending.put(tx.getHash(), tx);

        // Event listeners may re-enter so we cannot make assumptions about wallet state after this loop completes.
        try {
            BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
            BigInteger valueSentToMe = tx.getValueSentToMe(this);
            BigInteger newBalance = balance.add(valueSentToMe).subtract(valueSentFromMe);
            if (valueSentToMe.compareTo(BigInteger.ZERO) > 0)
                invokeOnCoinsReceived(tx, balance, newBalance);
            if (valueSentFromMe.compareTo(BigInteger.ZERO) > 0)
                invokeOnCoinsSent(tx, balance, newBalance);
        } catch (ScriptException e) {
            // Cannot happen as we just created this transaction ourselves.
            throw new RuntimeException(e);
        }

        checkState(isConsistent());
    }

    /**
     * Returns a set of all transactions in the wallet.
     *
     * @param includeDead     If true, transactions that were overridden by a double spend are included.
     * @param includeInactive If true, transactions that are on side chains (are unspendable) are included.
     */
    public synchronized Set<Transaction> getTransactions(boolean includeDead, boolean includeInactive) {
        Set<Transaction> all = new HashSet<Transaction>();
        all.addAll(unspent.values());
        all.addAll(spent.values());
        all.addAll(pending.values());
        if (includeDead)
            all.addAll(dead.values());
        if (includeInactive)
            all.addAll(inactive.values());
        return all;
    }

    /**
     * Returns a set of all WalletTransactions in the wallet.
     */
    public synchronized Iterable<WalletTransaction> getWalletTransactions() {
        HashSet<Transaction> pendingInactive = new HashSet<Transaction>();
        pendingInactive.addAll(pending.values());
        pendingInactive.retainAll(inactive.values());
        HashSet<Transaction> onlyPending = new HashSet<Transaction>();
        HashSet<Transaction> onlyInactive = new HashSet<Transaction>();
        onlyPending.addAll(pending.values());
        onlyPending.removeAll(pendingInactive);
        onlyInactive.addAll(inactive.values());
        onlyInactive.removeAll(pendingInactive);
        
        Set<WalletTransaction> all = new HashSet<WalletTransaction>();

        addWalletTransactionsToSet(all, Pool.UNSPENT, unspent.values());
        addWalletTransactionsToSet(all, Pool.SPENT, spent.values());
        addWalletTransactionsToSet(all, Pool.DEAD, dead.values());
        addWalletTransactionsToSet(all, Pool.PENDING, onlyPending);
        addWalletTransactionsToSet(all, Pool.INACTIVE, onlyInactive);
        addWalletTransactionsToSet(all, Pool.PENDING_INACTIVE, pendingInactive);
        return all;
    }

    private static synchronized void addWalletTransactionsToSet(Set<WalletTransaction> txs,
            Pool poolType, Collection<Transaction> pool) {
        for (Transaction tx : pool) {
            txs.add(new WalletTransaction(poolType, tx));
        }
    }
    
    public synchronized void addWalletTransaction(WalletTransaction wtx) {
        switch (wtx.getPool()) {
        case UNSPENT:
            unspent.put(wtx.getTransaction().getHash(), wtx.getTransaction());
            break;
        case SPENT:
            spent.put(wtx.getTransaction().getHash(), wtx.getTransaction());
            break;
        case PENDING:
            pending.put(wtx.getTransaction().getHash(), wtx.getTransaction());
            break;
        case DEAD:
            dead.put(wtx.getTransaction().getHash(), wtx.getTransaction());
            break;
        case INACTIVE:
            inactive.put(wtx.getTransaction().getHash(), wtx.getTransaction());
            break;
        case PENDING_INACTIVE:
            pending.put(wtx.getTransaction().getHash(), wtx.getTransaction());
            inactive.put(wtx.getTransaction().getHash(), wtx.getTransaction());
            break;
        default:
            throw new RuntimeException("Unknown wallet transaction type " + wtx.getPool());
        }
    }

    /**
     * Returns all non-dead, active transactions ordered by recency.
     */
    public List<Transaction> getTransactionsByTime() {
        return getRecentTransactions(0, false);
    }

    /**
     * Returns an list of N transactions, ordered by increasing age. Transactions on side chains are not included.
     * Dead transactions (overridden by double spends) are optionally included. <p>
     * <p/>
     * Note: the current implementation is O(num transactions in wallet). Regardless of how many transactions are
     * requested, the cost is always the same. In future, requesting smaller numbers of transactions may be faster
     * depending on how the wallet is implemented (eg if backed by a database).
     */
    public synchronized List<Transaction> getRecentTransactions(int numTransactions, boolean includeDead) {
        checkArgument(numTransactions >= 0);
        // Firstly, put all transactions into an array.
        int size = getPoolSize(WalletTransaction.Pool.UNSPENT) +
                getPoolSize(WalletTransaction.Pool.SPENT) +
                getPoolSize(WalletTransaction.Pool.PENDING);
        if (numTransactions > size || numTransactions == 0) {
            numTransactions = size;
        }
        ArrayList<Transaction> all = new ArrayList<Transaction>(getTransactions(includeDead, false));
        // Order by date.
        Collections.sort(all, Collections.reverseOrder(new Comparator<Transaction>() {
            public int compare(Transaction t1, Transaction t2) {
                return t1.getUpdateTime().compareTo(t2.getUpdateTime());
            }
        }));
        if (numTransactions == all.size()) {
            return all;
        } else {
            all.subList(numTransactions, all.size()).clear();
            return all;
        }
    }

    /**
     * Returns a transaction object given its hash, if it exists in this wallet, or null otherwise.
     */
    public synchronized Transaction getTransaction(Sha256Hash hash) {
        Transaction tx;
        if ((tx = pending.get(hash)) != null)
            return tx;
        else if ((tx = unspent.get(hash)) != null)
            return tx;
        else if ((tx = spent.get(hash)) != null)
            return tx;
        else if ((tx = inactive.get(hash)) != null)
            return tx;
        else if ((tx = dead.get(hash)) != null)
            return tx;
        return null;
    }

    /**
     * Deletes transactions which appeared above the given block height from the wallet, but does not touch the keys.
     * This is useful if you have some keys and wish to replay the block chain into the wallet in order to pick them up.
     */
    public synchronized void clearTransactions(int fromHeight) {
        if (fromHeight == 0) {
            unspent.clear();
            spent.clear();
            pending.clear();
            inactive.clear();
            dead.clear();
        } else {
            throw new UnsupportedOperationException();
        }
    }

    synchronized EnumSet<Pool> getContainingPools(Transaction tx) {
        EnumSet<Pool> result = EnumSet.noneOf(Pool.class);
        Sha256Hash txHash = tx.getHash();
        if (unspent.containsKey(txHash)) {
            result.add(Pool.UNSPENT);
        }
        if (spent.containsKey(txHash)) {
            result.add(Pool.SPENT);
        }
        if (pending.containsKey(txHash)) {
            result.add(Pool.PENDING);
        }
        if (inactive.containsKey(txHash)) {
            result.add(Pool.INACTIVE);
        }
        if (dead.containsKey(txHash)) {
            result.add(Pool.DEAD);
        }
        return result;
    }

    synchronized int getPoolSize(WalletTransaction.Pool pool) {
        switch (pool) {
            case UNSPENT:
                return unspent.size();
            case SPENT:
                return spent.size();
            case PENDING:
                return pending.size();
            case INACTIVE:
                return inactive.size();
            case DEAD:
                return dead.size();
            case ALL:
                return unspent.size() + spent.size() + pending.size() + inactive.size() + dead.size();
        }
        throw new RuntimeException("Unreachable");
    }

    /**
     * Statelessly creates a transaction that sends the given number of nanocoins to address. The change is sent to
     * {@link Wallet#getChangeAddress()}, so you must have added at least one key.<p>
     * <p/>
     * This method is stateless in the sense that calling it twice with the same inputs will result in two
     * Transaction objects which are equal. The wallet is not updated to track its pending status or to mark the
     * coins as spent until commitTx is called on the result.
     */
    public synchronized Transaction createSend(Address address, BigInteger nanocoins) {
        return createSend(address, nanocoins, getChangeAddress());
    }

    /**
     * Sends coins to the given address but does not broadcast the resulting pending transaction. It is still stored
     * in the wallet, so when the wallet is added to a {@link PeerGroup} or {@link Peer} the transaction will be
     * announced to the network.
     *
     * @param to Address to send the coins to.
     * @param nanocoins How many coins to send.
     * @return the Transaction that was created, or null if there are insufficient coins in thew allet.
     */
    public synchronized Transaction sendCoinsOffline(Address to, BigInteger nanocoins) {
        Transaction tx = createSend(to, nanocoins);
        if (tx == null)   // Not enough money! :-(
            return null;
        try {
            commitTx(tx);
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen unless there's a bug, as we just created this ourselves.
        }
        return tx;
    }

    /**
     * Sends coins to the given address, via the given {@link PeerGroup}. Change is returned to {@link Wallet#getChangeAddress()}.
     * The transaction will be announced to any connected nodes asynchronously. If you would like to know when
     * the transaction was successfully sent to at least one node, use 
     * {@link Wallet#sendCoinsOffline(Address, java.math.BigInteger)} and then {@link PeerGroup#broadcastTransaction(Transaction)}
     * on the result to obtain a {@link java.util.concurrent.Future<Transaction>}.
     *
     * @param peerGroup a PeerGroup to use for broadcast.
     * @param to        Which address to send coins to.
     * @param nanocoins How many nanocoins to send. You can use Utils.toNanoCoins() to calculate this.
     * @return the Transaction
     * @throws IOException if there was a problem broadcasting the transaction
     */
    public synchronized Transaction sendCoinsAsync(PeerGroup peerGroup, Address to, BigInteger nanocoins) throws IOException {
        Transaction tx = sendCoinsOffline(to, nanocoins);
        if (tx == null)
            return null;  // Not enough money.
        // Just throw away the Future here. If the user wants it, they can call sendCoinsOffline/broadcastTransaction
        // themselves.
        peerGroup.broadcastTransaction(tx);
        return tx;
    }

    /**
     * Sends coins to the given address, via the given {@link PeerGroup}. Change is returned to {@link Wallet#getChangeAddress()}.
     * The method will block until the transaction has been announced to at least one node.
     *
     * @param peerGroup a PeerGroup to use for broadcast or null.
     * @param to        Which address to send coins to.
     * @param nanocoins How many nanocoins to send. You can use Utils.toNanoCoins() to calculate this.
     * @return The {@link Transaction} that was created or null if there was insufficient balance to send the coins.
     */
    public synchronized Transaction sendCoins(PeerGroup peerGroup, Address to, BigInteger nanocoins) {
        Transaction tx = sendCoinsOffline(to, nanocoins);
        if (tx == null)
            return null;  // Not enough money.
        try {
            return peerGroup.broadcastTransaction(tx).get();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Sends coins to the given address, via the given {@link Peer}. Change is returned to {@link Wallet#getChangeAddress()}.
     * If an exception is thrown by {@link Peer#sendMessage(Message)} the transaction is still committed, so the
     * pending transaction must be broadcast <b>by you</b> at some other time.
     *
     * @param to        Which address to send coins to.
     * @param nanocoins How many nanocoins to send. You can use Utils.toNanoCoins() to calculate this.
     * @return The {@link Transaction} that was created or null if there was insufficient balance to send the coins.
     * @throws IOException if there was a problem broadcasting the transaction
     */
    public synchronized Transaction sendCoins(Peer peer, Address to, BigInteger nanocoins) throws IOException {
        // TODO: This API is fairly questionable and the function isn't tested. If anything goes wrong during sending
        // on the peer you don't get access to the created Transaction object and must fish it out of the wallet then
        // do your own retry later.

        Transaction tx = createSend(to, nanocoins);
        if (tx == null)   // Not enough money! :-(
            return null;
        try {
            commitTx(tx);
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen unless there's a bug, as we just created this ourselves.
        }
        peer.sendMessage(tx);
        return tx;
    }

    /**
     * Creates a transaction that sends $coins.$cents BTC to the given address.<p>
     * <p/>
     * IMPORTANT: This method does NOT update the wallet. If you call createSend again you may get two transactions
     * that spend the same coins. You have to call commitTx on the created transaction to prevent this,
     * but that should only occur once the transaction has been accepted by the network. This implies you cannot have
     * more than one outstanding sending tx at once.
     *
     * @param address       The BitCoin address to send the money to.
     * @param nanocoins     How much currency to send, in nanocoins.
     * @param changeAddress Which address to send the change to, in case we can't make exactly the right value from
     *                      our coins. This should be an address we own (is in the keychain).
     * @return a new {@link Transaction} or null if we cannot afford this send.
     */
    public synchronized Transaction createSend(Address address, BigInteger nanocoins, Address changeAddress) {
        log.info("Creating send tx to " + address.toString() + " for " +
                bitcoinValueToFriendlyString(nanocoins));

        Transaction sendTx = new Transaction(params);
        sendTx.addOutput(nanocoins, address);

        if (completeTx(sendTx, changeAddress)) {
            return sendTx;
        } else {
            return null;
        }
    }

    /**
     * Takes a transaction with arbitrary outputs, gathers the necessary inputs for spending, and signs it
     * @param sendTx           The transaction to complete
     * @param changeAddress    Which address to send the change to, in case we can't make exactly the right value from
     *                         our coins. This should be an address we own (is in the keychain).
     * @return False if we cannot afford this send, true otherwise
     */
    public synchronized boolean completeTx(Transaction sendTx, Address changeAddress) {
        // Calculate the transaction total
        BigInteger nanocoins = BigInteger.ZERO;
        for(TransactionOutput output : sendTx.getOutputs()) {
            nanocoins = nanocoins.add(output.getValue());
        }

        log.info("Completing send tx with {} outputs totalling {}", sendTx.getOutputs().size(), bitcoinValueToFriendlyString(nanocoins));

        // To send money to somebody else, we need to do gather up transactions with unspent outputs until we have
        // sufficient value. Many coin selection algorithms are possible, we use a simple but suboptimal one.
        // TODO: Sort coins so we use the smallest first, to combat wallet fragmentation and reduce fees.
        BigInteger valueGathered = BigInteger.ZERO;
        List<TransactionOutput> gathered = new LinkedList<TransactionOutput>();
        for (Transaction tx : unspent.values()) {
            for (TransactionOutput output : tx.getOutputs()) {
                if (!output.isAvailableForSpending()) continue;
                if (!output.isMine(this)) continue;
                gathered.add(output);
                valueGathered = valueGathered.add(output.getValue());
            }
            if (valueGathered.compareTo(nanocoins) >= 0) break;
        }
        // Can we afford this?
        if (valueGathered.compareTo(nanocoins) < 0) {
            log.info("Insufficient value in wallet for send, missing " +
                    bitcoinValueToFriendlyString(nanocoins.subtract(valueGathered)));
            // TODO: Should throw an exception here.
            return false;
        }
        checkState(gathered.size() > 0);
        sendTx.getConfidence().setConfidenceType(TransactionConfidence.ConfidenceType.NOT_SEEN_IN_CHAIN);
        BigInteger change = valueGathered.subtract(nanocoins);
        if (change.compareTo(BigInteger.ZERO) > 0) {
            // The value of the inputs is greater than what we want to send. Just like in real life then,
            // we need to take back some coins ... this is called "change". Add another output that sends the change
            // back to us.
            log.info("  with " + bitcoinValueToFriendlyString(change) + " coins change");
            sendTx.addOutput(new TransactionOutput(params, sendTx, change, changeAddress));
        }
        for (TransactionOutput output : gathered) {
            sendTx.addInput(output);
        }

        // Now sign the inputs, thus proving that we are entitled to redeem the connected outputs.
        try {
            sendTx.signInputs(Transaction.SigHash.ALL, this);
        } catch (ScriptException e) {
            // If this happens it means an output script in a wallet tx could not be understood. That should never
            // happen, if it does it means the wallet has got into an inconsistent state.
            throw new RuntimeException(e);
        }
        log.info("  completed {}", sendTx.getHashAsString());
        return true;
    }

    /**
     * Takes a transaction with arbitrary outputs, gathers the necessary inputs for spending, and signs it.
     * Change goes to {@link Wallet#getChangeAddress()}
     * @param sendTx           The transaction to complete
     * @return False if we cannot afford this send, true otherwise
     */
    public synchronized boolean completeTx(Transaction sendTx) {
        return completeTx(sendTx, getChangeAddress());
    }

    synchronized Address getChangeAddress() {
        // For now let's just pick the first key in our keychain. In future we might want to do something else to
        // give the user better privacy here, eg in incognito mode.
        checkState(keychain.size() > 0, "Can't send value without an address to use for receiving change");
        ECKey first = keychain.get(0);
        return first.toAddress(params);
    }

    /**
     * Adds the given ECKey to the wallet. There is currently no way to delete keys (that would result in coin loss).
     */
    public synchronized void addKey(ECKey key) {
        checkArgument(!keychain.contains(key), "Key already present");
        keychain.add(key);
    }

    /**
     * Locates a keypair from the keychain given the hash of the public key. This is needed when finding out which
     * key we need to use to redeem a transaction output.
     *
     * @return ECKey object or null if no such key was found.
     */
    public synchronized ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        for (ECKey key : keychain) {
            if (Arrays.equals(key.getPubKeyHash(), pubkeyHash)) return key;
        }
        return null;
    }

    /**
     * Returns true if this wallet contains a public key which hashes to the given hash.
     */
    public synchronized boolean isPubKeyHashMine(byte[] pubkeyHash) {
        return findKeyFromPubHash(pubkeyHash) != null;
    }

    /**
     * Locates a keypair from the keychain given the raw public key bytes.
     *
     * @return ECKey or null if no such key was found.
     */
    public synchronized ECKey findKeyFromPubKey(byte[] pubkey) {
        for (ECKey key : keychain) {
            if (Arrays.equals(key.getPubKey(), pubkey)) return key;
        }
        return null;
    }

    /**
     * Returns true if this wallet contains a keypair with the given public key.
     */
    public synchronized boolean isPubKeyMine(byte[] pubkey) {
        return findKeyFromPubKey(pubkey) != null;
    }

    /**
     * It's possible to calculate a wallets balance from multiple points of view. This enum selects which
     * getBalance() should use.<p>
     * <p/>
     * Consider a real-world example: you buy a snack costing $5 but you only have a $10 bill. At the start you have
     * $10 viewed from every possible angle. After you order the snack you hand over your $10 bill. From the
     * perspective of your wallet you have zero dollars (AVAILABLE). But you know in a few seconds the shopkeeper
     * will give you back $5 change so most people in practice would say they have $5 (ESTIMATED).<p>
     */
    public enum BalanceType {
        /**
         * Balance calculated assuming all pending transactions are in fact included into the best chain by miners.
         * This is the right balance to show in user interfaces.
         */
        ESTIMATED,

        /**
         * Balance that can be safely used to create new spends. This is all confirmed unspent outputs minus the ones
         * spent by pending transactions, but not including the outputs of those pending transactions.
         */
        AVAILABLE
    }

    /**
     * Returns the AVAILABLE balance of this wallet. See {@link BalanceType#AVAILABLE} for details on what this
     * means.<p>
     * <p/>
     * Note: the estimated balance is usually the one you want to show to the end user - however attempting to
     * actually spend these coins may result in temporary failure. This method returns how much you can safely
     * provide to {@link Wallet#createSend(Address, java.math.BigInteger)}.
     */
    public synchronized BigInteger getBalance() {
        return getBalance(BalanceType.AVAILABLE);
    }

    /**
     * Returns the balance of this wallet as calculated by the provided balanceType.
     */
    public synchronized BigInteger getBalance(BalanceType balanceType) {
        BigInteger available = BigInteger.ZERO;
        for (Transaction tx : unspent.values()) {
            for (TransactionOutput output : tx.getOutputs()) {
                if (!output.isMine(this)) continue;
                if (!output.isAvailableForSpending()) continue;
                available = available.add(output.getValue());
            }
        }
        if (balanceType == BalanceType.AVAILABLE)
            return available;
        checkState(balanceType == BalanceType.ESTIMATED);
        // Now add back all the pending outputs to assume the transaction goes through.
        BigInteger estimated = available;
        for (Transaction tx : pending.values()) {
            for (TransactionOutput output : tx.getOutputs()) {
                if (!output.isMine(this)) continue;
                estimated = estimated.add(output.getValue());
            }
        }
        return estimated;
    }

    @Override
    public synchronized String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(String.format("Wallet containing %s BTC in:\n", bitcoinValueToFriendlyString(getBalance())));
        builder.append(String.format("  %d unspent transactions\n", unspent.size()));
        builder.append(String.format("  %d spent transactions\n", spent.size()));
        builder.append(String.format("  %d pending transactions\n", pending.size()));
        builder.append(String.format("  %d inactive transactions\n", inactive.size()));
        builder.append(String.format("  %d dead transactions\n", dead.size()));
        // Do the keys.
        builder.append("\nKeys:\n");
        for (ECKey key : keychain) {
            builder.append("  addr:");
            builder.append(key.toAddress(params));
            builder.append(" ");
            builder.append(key.toString());
            builder.append("\n");
        }
        // Print the transactions themselves
        if (unspent.size() > 0) {
            builder.append("\nUNSPENT:\n");
            toStringHelper(builder, unspent);
        }
        if (spent.size() > 0) {
            builder.append("\nSPENT:\n");
            toStringHelper(builder, spent);
        }
        if (pending.size() > 0) {
            builder.append("\nPENDING:\n");
            toStringHelper(builder, pending);
        }
        if (inactive.size() > 0) {
            builder.append("\nINACTIVE:\n");
            toStringHelper(builder, inactive);
        }
        if (dead.size() > 0) {
            builder.append("\nDEAD:\n");
            toStringHelper(builder, dead);
        }
        return builder.toString();
    }

    private void toStringHelper(StringBuilder builder, Map<Sha256Hash, Transaction> transactionMap) {
        for (Transaction tx : transactionMap.values()) {
            try {
                builder.append("Sends ");
                builder.append(Utils.bitcoinValueToFriendlyString(tx.getValueSentFromMe(this)));
                builder.append(" and receives ");
                builder.append(Utils.bitcoinValueToFriendlyString(tx.getValueSentToMe(this)));
                builder.append(", total value ");
                builder.append(Utils.bitcoinValueToFriendlyString(tx.getValue(this)));
                builder.append(".\n");
            } catch (ScriptException e) {
                // Ignore and don't print this line.
            }
            builder.append(tx);
        }
    }

    /**
     * Called by the {@link BlockChain} when the best chain (representing total work done) has changed. In this case,
     * we need to go through our transactions and find out if any have become invalid. It's possible for our balance
     * to go down in this case: money we thought we had can suddenly vanish if the rest of the network agrees it
     * should be so.<p>
     *
     * The oldBlocks/newBlocks lists are ordered height-wise from top first to bottom last.
     */
    synchronized void reorganize(List<StoredBlock> oldBlocks, List<StoredBlock> newBlocks) throws VerificationException {
        // This runs on any peer thread with the block chain synchronized.
        //
        // The reorganize functionality of the wallet is tested in ChainSplitTests.
        //
        // For each transaction we track which blocks they appeared in. Once a re-org takes place we have to find all
        // transactions in the old branch, all transactions in the new branch and find the difference of those sets.
        //
        // receive() has been called on the block that is triggering the re-org before this is called.

        List<Sha256Hash> oldBlockHashes = new ArrayList<Sha256Hash>(oldBlocks.size());
        List<Sha256Hash> newBlockHashes = new ArrayList<Sha256Hash>(newBlocks.size());
        log.info("Old part of chain (top to bottom):");
        for (StoredBlock b : oldBlocks) {
            log.info("  {}", b.getHeader().getHashAsString());
            oldBlockHashes.add(b.getHeader().getHash());
        }
        log.info("New part of chain (top to bottom):");
        for (StoredBlock b : newBlocks) {
            log.info("  {}", b.getHeader().getHashAsString());
            newBlockHashes.add(b.getHeader().getHash());
        }

        // Transactions that appear in the old chain segment.
        Map<Sha256Hash, Transaction> oldChainTransactions = new HashMap<Sha256Hash, Transaction>();
        // Transactions that appear in the old chain segment and NOT the new chain segment.
        Map<Sha256Hash, Transaction> onlyOldChainTransactions = new HashMap<Sha256Hash, Transaction>();
        // Transactions that appear in the new chain segment.
        Map<Sha256Hash, Transaction> newChainTransactions = new HashMap<Sha256Hash, Transaction>();
        // Transactions that don't appear in either the new or the old section, ie, the shared trunk.
        Map<Sha256Hash, Transaction> commonChainTransactions = new HashMap<Sha256Hash, Transaction>();

        Map<Sha256Hash, Transaction> all = new HashMap<Sha256Hash, Transaction>();
        all.putAll(unspent);
        all.putAll(spent);
        all.putAll(inactive);
        for (Transaction tx : all.values()) {
            Collection<Sha256Hash> appearsIn = tx.getAppearsInHashes();
            checkNotNull(appearsIn);
            // If the set of blocks this transaction appears in is disjoint with one of the chain segments it means
            // the transaction was never incorporated by a miner into that side of the chain.
            boolean inOldSection = !Collections.disjoint(appearsIn, oldBlockHashes);
            boolean inNewSection = !Collections.disjoint(appearsIn, newBlockHashes);
            boolean inCommonSection = !inNewSection && !inOldSection;

            if (inCommonSection) {
                boolean alreadyPresent = commonChainTransactions.put(tx.getHash(), tx) != null;
                checkState(!alreadyPresent, "Transaction appears twice in common chain segment");
            } else {
                if (inOldSection) {
                    boolean alreadyPresent = oldChainTransactions.put(tx.getHash(), tx) != null;
                    checkState(!alreadyPresent, "Transaction appears twice in old chain segment");
                    if (!inNewSection) {
                        alreadyPresent = onlyOldChainTransactions.put(tx.getHash(), tx) != null;
                        checkState(!alreadyPresent, "Transaction appears twice in only-old map");
                    }
                }
                if (inNewSection) {
                    boolean alreadyPresent = newChainTransactions.put(tx.getHash(), tx) != null;
                    checkState(!alreadyPresent, "Transaction appears twice in new chain segment");
                }
            }
        }

        // If there is no difference it means we have nothing we need to do and the user does not care.
        boolean affectedUs = !oldChainTransactions.equals(newChainTransactions);
        log.info(affectedUs ? "Re-org affected our transactions" : "Re-org had no effect on our transactions");
        if (!affectedUs) return;

        // For simplicity we will reprocess every transaction to ensure it's in the right bucket and has the right
        // connections. Attempting to update each one with minimal work is possible but complex and was leading to
        // edge cases that were hard to fix. As re-orgs are rare the amount of work this implies should be manageable
        // unless the user has an enormous wallet. As an optimization fully spent transactions buried deeper than
        // 1000 blocks could be put into yet another bucket which we never touch and assume re-orgs cannot affect.

        for (Transaction tx : onlyOldChainTransactions.values()) log.info("  Only Old: {}", tx.getHashAsString());
        for (Transaction tx : oldChainTransactions.values()) log.info("  Old: {}", tx.getHashAsString());
        for (Transaction tx : newChainTransactions.values()) log.info("  New: {}", tx.getHashAsString());

        // Break all the existing connections.
        for (Transaction tx : all.values())
            tx.disconnectInputs();
        for (Transaction tx : pending.values())
            tx.disconnectInputs();
        // Reconnect the transactions in the common part of the chain.
        for (Transaction tx : commonChainTransactions.values()) {
            TransactionInput badInput = tx.connectForReorganize(all);
            checkState(badInput == null, "Failed to connect %s, %s", tx.getHashAsString(),
                       badInput == null ? "" : badInput.toString());
        }
        // Recalculate the unspent/spent buckets for the transactions the re-org did not affect.
        log.info("Moving transactions");
        unspent.clear();
        spent.clear();
        inactive.clear();
        for (Transaction tx : commonChainTransactions.values()) {
            int unspentOutputs = 0;
            for (TransactionOutput output : tx.getOutputs()) {
                if (output.isAvailableForSpending() && output.isMine(this)) unspentOutputs++;
            }
            if (unspentOutputs > 0) {
                log.info("  TX {} ->unspent", tx.getHashAsString());
                unspent.put(tx.getHash(), tx);
            } else {
                log.info("  TX {} ->spent", tx.getHashAsString());
                spent.put(tx.getHash(), tx);
            }
        }
        // Inform all transactions that exist only in the old chain that they have moved, so they can update confidence
        // and timestamps. Transactions will be told they're on the new best chain when the blocks are replayed.
        for (Transaction tx : onlyOldChainTransactions.values()) {
            tx.notifyNotOnBestChain();
        }
        // Now replay the act of receiving the blocks that were previously in a side chain. This will:
        //   - Move any transactions that were pending and are now accepted into the right bucket.
        //   - Connect the newly active transactions.
        Collections.reverse(newBlocks);  // Need bottom-to-top but we get top-to-bottom.
        for (StoredBlock b : newBlocks) {
            log.info("Replaying block {}", b.getHeader().getHashAsString());
            Set<Transaction> txns = new HashSet<Transaction>();
            Sha256Hash blockHash = b.getHeader().getHash();
            for (Transaction tx : newChainTransactions.values()) {
                if (tx.getAppearsInHashes().contains(blockHash)) {
                    txns.add(tx);
                    log.info("  containing tx {}", tx.getHashAsString());
                }
            }
            for (Transaction t : txns) {
                try {
                    receive(t, b, BlockChain.NewBlockType.BEST_CHAIN, true);
                } catch (ScriptException e) {
                    throw new RuntimeException(e);  // Cannot happen as these blocks were already verified.
                }
            }
        }

        // Find the transactions that didn't make it into the new chain yet. For each input, try to connect it to the
        // transactions that are in {spent,unspent,pending}. Check the status of each input. For inactive
        // transactions that only send us money, we put them into the inactive pool where they sit around waiting for
        // another re-org or re-inclusion into the main chain. For inactive transactions where we spent money we must
        // put them back into the pending pool if we can reconnect them, so we don't create a double spend whilst the
        // network heals itself.
        Map<Sha256Hash, Transaction> pool = new HashMap<Sha256Hash, Transaction>();
        pool.putAll(unspent);
        pool.putAll(spent);
        pool.putAll(pending);
        Map<Sha256Hash, Transaction> toReprocess = new HashMap<Sha256Hash, Transaction>();
        toReprocess.putAll(onlyOldChainTransactions);
        toReprocess.putAll(pending);
        log.info("Reprocessing transactions not in new best chain:");
        // Note, we must reprocess dead transactions first. The reason is that if there is a double spend across
        // chains from our own coins we get a complicated situation:
        //
        // 1) We switch to a new chain (B) that contains a double spend overriding a pending transaction. The
        //    pending transaction goes dead.
        // 2) We switch BACK to the first chain (A). The dead transaction must go pending again.
        // 3) We resurrect the transactions that were in chain (B) and assume the miners will start work on putting them
        //    in to the chain, but it's not possible because it's a double spend. So now that transaction must become
        //    dead instead of pending.
        //
        // This only occurs when we are double spending our own coins.
        for (Transaction tx : dead.values()) {
            reprocessUnincludedTxAfterReorg(pool, tx);
        }
        for (Transaction tx : toReprocess.values()) {
            reprocessUnincludedTxAfterReorg(pool, tx);
        }

        log.info("post-reorg balance is {}", Utils.bitcoinValueToFriendlyString(getBalance()));

        // Inform event listeners that a re-org took place. They should save the wallet at this point.
        EventListenerInvoker.invoke(eventListeners, new EventListenerInvoker<WalletEventListener>() {
            @Override
            public void invoke(WalletEventListener listener) {
                listener.onReorganize(Wallet.this);
            }
        });
        checkState(isConsistent());
    }

    private void reprocessUnincludedTxAfterReorg(Map<Sha256Hash, Transaction> pool, Transaction tx) {
        log.info("TX {}", tx.getHashAsString());
        int numInputs = tx.getInputs().size();
        int noSuchTx = 0;
        int success = 0;
        boolean isDead = false;
        // The transactions that we connected inputs to, so we can go back later and move them into the right
        // bucket if all their outputs got spent.
        Set<Transaction> connectedTransactions = new TreeSet<Transaction>();
        for (TransactionInput input : tx.getInputs()) {
            if (input.isCoinBase()) {
                // Input is not in our wallet so there is "no such input tx", bit of an abuse.
                noSuchTx++;
                continue;
            }
            TransactionInput.ConnectionResult result = input.connect(pool, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
            if (result == TransactionInput.ConnectionResult.SUCCESS) {
                success++;
                TransactionOutput connectedOutput = checkNotNull(input.getConnectedOutput(pool));
                connectedTransactions.add(checkNotNull(connectedOutput.parentTransaction));
            } else if (result == TransactionInput.ConnectionResult.NO_SUCH_TX) {
                noSuchTx++;
            } else if (result == TransactionInput.ConnectionResult.ALREADY_SPENT) {
                isDead = true;
                // This transaction was replaced by a double spend on the new chain. Did you just reverse
                // your own transaction? I hope not!!
                log.info("   ->dead, will not confirm now unless there's another re-org", tx.getHashAsString());
                TransactionOutput doubleSpent = input.getConnectedOutput(pool);
                Transaction replacement = doubleSpent.getSpentBy().getParentTransaction();
                dead.put(tx.getHash(), tx);
                pending.remove(tx.getHash());
                // This updates the tx confidence type automatically.
                tx.getConfidence().setOverridingTransaction(replacement);
                invokeOnTransactionConfidenceChanged(tx);
                break;
            }
        }
        if (isDead) return;

        if (noSuchTx == numInputs) {
            log.info("   ->inactive", tx.getHashAsString());
            inactive.put(tx.getHash(), tx);
        } else if (success == numInputs - noSuchTx) {
            // All inputs are either valid for spending or don't come from us. Miners are trying to reinclude it.
            log.info("   ->pending", tx.getHashAsString());
            pending.put(tx.getHash(), tx);
            dead.remove(tx.getHash());
        }

        // The act of re-connecting this un-included transaction may have caused other transactions to become fully
        // spent so move them into the right bucket here to keep performance good.
        for (Transaction maybeSpent : connectedTransactions) {
            maybeMoveTxToSpent(maybeSpent, "reorg");
        }
    }

    private void invokeOnTransactionConfidenceChanged(final Transaction tx) {
        EventListenerInvoker.invoke(eventListeners, new EventListenerInvoker<WalletEventListener>() {
            @Override
            public void invoke(WalletEventListener listener) {
                listener.onTransactionConfidenceChanged(Wallet.this, tx);
            }
        });
    }


    /**
     * Returns an immutable view of the transactions currently waiting for network confirmations.
     */
    public synchronized Collection<Transaction> getPendingTransactions() {
        return Collections.unmodifiableCollection(pending.values());
    }

    /**
     * Returns the earliest creation time of the keys in this wallet, in seconds since the epoch, ie the min of 
     * {@link com.google.bitcoin.core.ECKey#getCreationTimeSeconds()}. This can return zero if at least one key does
     * not have that data (was created before key timestamping was implemented). <p>
     *     
     * This method is most often used in conjunction with {@link PeerGroup#setFastCatchupTimeSecs(long)} in order to
     * optimize chain download for new users of wallet apps. Backwards compatibility notice: if you get zero from this
     * method, you can instead use the time of the first release of your software, as it's guaranteed no users will
     * have wallets pre-dating this time. <p>
     * 
     * If there are no keys in the wallet, the current time is returned.
     */
    public synchronized long getEarliestKeyCreationTime() {
        if (keychain.size() == 0) {
            return Utils.now().getTime() / 1000;
        }
        long earliestTime = Long.MAX_VALUE;
        for (ECKey key : keychain) {
            earliestTime = Math.min(key.getCreationTimeSeconds(), earliestTime);
        }
        return earliestTime;
    }
    
    // This object is used to receive events from a Peer or PeerGroup. Currently it is only used to receive
    // transactions. Note that it does NOT pay attention to block message because they will be received from the
    // BlockChain object along with extra data we need for correct handling of re-orgs.
    private transient PeerEventListener peerEventListener;

    /**
     * The returned object can be used to connect the wallet to a {@link Peer} or {@link PeerGroup} in order to
     * receive and process blocks and transactions.
     */
    public synchronized PeerEventListener getPeerEventListener() {
        if (peerEventListener == null) {
            // Instantiate here to avoid issues with wallets resurrected from serialized copies.
            peerEventListener = new AbstractPeerEventListener() {
                @Override
                public void onTransaction(Peer peer, Transaction t) {
                    // Runs locked on a peer thread.
                    try {
                        receivePending(t);
                    } catch (VerificationException e) {
                        log.warn("Received broadcast transaction that does not validate: {}", t);
                        log.warn("VerificationException caught", e);
                    } catch (ScriptException e) {
                        log.warn("Received broadcast transaction with not understood scripts: {}", t);
                        log.warn("ScriptException caught", e);
                    }
                }
            };
        }
        return peerEventListener;
    }

    public Sha256Hash getLastBlockSeenHash() {
        return lastBlockSeenHash;
    }

    public void setLastBlockSeenHash(Sha256Hash lastBlockSeenHash) {
        this.lastBlockSeenHash = lastBlockSeenHash;
    }
}
