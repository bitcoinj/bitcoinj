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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.util.*;

import static com.google.bitcoin.core.Utils.bitcoinValueToFriendlyString;

/**
 * A Wallet stores keys and a record of transactions that have not yet been spent. Thus, it is capable of
 * providing transactions on demand that meet a given combined value. Once a transaction
 * output is used, it is removed from the wallet as it is no longer available for spending.<p>
 *
 * The Wallet is read and written from disk, so be sure to follow the Java serialization
 * versioning rules here. We use the built in Java serialization to avoid the need to
 * pull in a potentially large (code-size) third party serialization library.<p>
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
    //
    // Re-orgs:
    // 1. Tx is present in old chain and not present in new chain
    //       <-unspent/spent  ->inactive
    //
    //       These newly inactive transactions will (if they are relevant to us) eventually come back via receive()
    //       as miners resurrect them and re-include into the new best chain. Until then we do NOT consider them
    //       pending as it's possible some of the transactions have become invalid (eg because the new chain contains
    //       a double spend). This could cause some confusing UI changes for the user but these events should be very
    //       rare.
    //
    // 2. Tx is not present in old chain and is present in new chain
    //       <-inactive  and  ->unspent/spent
    //
    // Balance:
    // 1. Sum up all unspent outputs of the transactions in unspent.
    // 2. Subtract the inputs of transactions in pending.
    // 3. In future: re-add the outputs of pending transactions that are mine. Don't do this today because those
    //    change outputs would not be considered spendable.

    /**
     * Map of txhash->Transactions that have not made it into the best chain yet. These transactions inputs count as
     * spent for the purposes of calculating our balance but their outputs are not available for spending yet. This
     * means after a spend, our balance can actually go down temporarily before going up again!
     */
    final Map<Sha256Hash, Transaction> pending;

    /**
     * Map of txhash->Transactions where the Transaction has unspent outputs. These are transactions we can use
     * to pay other people and so count towards our balance. Transactions only appear in this map if they are part
     * of the best chain. Transactions we have broacast that are not confirmed yet appear in pending even though they
     * may have unspent "change" outputs.<p>
     *
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
     *
     * Transactions only appear in this map if they are part of the best chain.
     */
    final Map<Sha256Hash, Transaction> spent;

    /**
     * An inactive transaction is one that is seen only in a block that is not a part of the best chain. We keep it
     * around in case a re-org promotes a different chain to be the best. In this case some (not necessarily all)
     * inactive transactions will be moved out to unspent and spent, and some might be moved in.<p>
     *
     * Note that in the case where a transaction appears in both the best chain and a side chain as well, it is not
     * placed in this map. It's an error for a transaction to be in both the inactive pool and unspent/spent.
     */
    private Map<Sha256Hash, Transaction> inactive;

    /** A list of public/private EC keys owned by this user. */
    public final ArrayList<ECKey> keychain;

    private final NetworkParameters params;

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
        eventListeners = new ArrayList<WalletEventListener>();
    }

    /**
     * Uses Java serialization to save the wallet to the given file.
     */
    public synchronized void saveToFile(File f) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(f));
        oos.writeObject(this);
        oos.close();
    }

    /**
     * Returns a wallet deserialized from the given file.
     */
    public static Wallet loadFromFile(File f) throws IOException {
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(new FileInputStream(f));
            return (Wallet) ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } finally {
            if (ois != null) ois.close();
        }
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        eventListeners = new ArrayList<WalletEventListener>();
    }

    /**
     * Returns true if the given transaction is present in the wallet, comparing by hash value (not by object
     * reference). So you can create a transaction object from scratch and get true from this method if the
     * transaction is logically equal.
     */
    public synchronized boolean isTransactionPresent(Transaction transaction) {
        // TODO: Redefine or delete this method.
        Sha256Hash hash = transaction.getHash();
        return unspent.containsKey(hash) || spent.containsKey(hash);
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
    synchronized void receive(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType) throws VerificationException, ScriptException {
        // Runs in a peer thread.
        BigInteger prevBalance = getBalance();

        Sha256Hash txHash = tx.getHash();

        boolean bestChain = blockType == BlockChain.NewBlockType.BEST_CHAIN;
        boolean sideChain = blockType == BlockChain.NewBlockType.SIDE_CHAIN;

        BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
        BigInteger valueSentToMe = tx.getValueSentToMe(this);
        BigInteger valueDifference = valueSentToMe.subtract(valueSentFromMe);

        log.info("Wallet: Received tx" + (sideChain ? " on a side chain" :"") + " for " +
                    bitcoinValueToFriendlyString(valueDifference) + " BTC");

        // If this transaction is already in the wallet we may need to move it into a different pool. At the very
        // least we need to ensure we're manipulating the canonical object rather than a duplicate.
        Transaction wtx = null;
        if ((wtx = pending.remove(txHash)) != null) {
            log.info("  <-pending");
            // A transaction we created appeared in a block. Probably this is a spend we broadcast that has been
            // accepted by the network.
            //
            // Mark the tx as appearing in this block so we can find it later after a re-org.
            wtx.addBlockAppearance(block);
            if (bestChain) {
                if (valueSentToMe.equals(BigInteger.ZERO)) {
                    // There were no change transactions so this tx is fully spent.
                    log.info("  ->spent");
                    boolean alreadyPresent = spent.put(wtx.getHash(), wtx) != null;
                    assert !alreadyPresent : "TX in both pending and spent pools";
                } else {
                    // There was change back to us, or this tx was purely a spend back to ourselves (perhaps for
                    // anonymization purposes).
                    log.info("  ->unspent");
                    boolean alreadyPresent = unspent.put(wtx.getHash(), wtx) != null;
                    assert !alreadyPresent : "TX in both pending and unspent pools";
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
                boolean alreadyPresent = inactive.put(wtx.getHash(), wtx) != null;
                if (alreadyPresent)
                    log.info("Saw a transaction be incorporated into multiple independent side chains");
                // Put it back into the pending pool, because 'pending' means 'waiting to be included in best chain'.
                pending.put(wtx.getHash(), wtx);
            }
        } else {
            // Mark the tx as appearing in this block so we can find it later after a re-org.
            tx.addBlockAppearance(block);
            // This TX didn't originate with us. It could be sending us coins and also spending our own coins if keys
            // are being shared between different wallets.
            if (sideChain) {
                log.info("  ->inactive");
                inactive.put(tx.getHash(), tx);
            } else if (bestChain) {
                processTxFromBestChain(tx);
            }
        }

        log.info("Balance is now: " + bitcoinValueToFriendlyString(getBalance()));

        // Inform anyone interested that we have new coins. Note: we may be re-entered by the event listener,
        // so we must not make assumptions about our state after this loop returns! For example,
        // the balance we just received might already be spent!
        if (bestChain && valueDifference.compareTo(BigInteger.ZERO) > 0) {
            for (WalletEventListener l : eventListeners) {
                synchronized (l) {
                    l.onCoinsReceived(this, tx, prevBalance, getBalance());
                }
            }
        }
    }

    /**
     * Handle when a transaction becomes newly active on the best chain, either due to receiving a new block or a
     * re-org making inactive transactions active.
     */
    private void processTxFromBestChain(Transaction tx) throws VerificationException {
        // This TX may spend our existing outputs even though it was not pending. This can happen in unit
        // tests and if keys are moved between wallets.
        updateForSpends(tx);
        if (!tx.getValueSentToMe(this).equals(BigInteger.ZERO)) {
            // It's sending us coins.
            log.info("  ->unspent");
            boolean alreadyPresent = unspent.put(tx.getHash(), tx) != null;
            assert !alreadyPresent : "TX was received twice";
        } else {
            // It spent some of our coins and did not send us any.
            log.info("  ->spent");
            boolean alreadyPresent = spent.put(tx.getHash(), tx) != null;
            assert !alreadyPresent : "TX was received twice";
        }
    }

    /**
     * Updates the wallet by checking if this TX spends any of our unspent outputs. This is not used normally because
     * when we receive our own spends, we've already marked the outputs as spent previously (during tx creation) so
     * there's no need to go through and do it again.
     */
    private void updateForSpends(Transaction tx) throws VerificationException {
        for (TransactionInput input : tx.inputs) {
            if (input.outpoint.connect(unspent.values())) {
                TransactionOutput output = input.outpoint.getConnectedOutput();
                assert !output.isSpent : "Double spend accepted by the network?";
                log.info("  Saw some of my unspent outputs be spent by someone else who has my keys.");
                log.info("  Total spent value is " + bitcoinValueToFriendlyString(output.getValue()));
                output.isSpent = true;
                Transaction connectedTx = input.outpoint.fromTx;
                if (connectedTx.getValueSentToMe(this, false).equals(BigInteger.ZERO)) {
                    // There's nothing left I can spend in this transaction.
                    if (unspent.remove(connectedTx.getHash()) != null);
                        log.info("  prevtx <-unspent");
                    spent.put(connectedTx.getHash(), connectedTx);
                    log.info("  prevtx ->spent");
                }
            }
        }
    }

    /**
     * Adds an event listener object. Methods on this object are called when something interesting happens,
     * like receiving money.<p>
     *
     * Threading: Event listener methods are dispatched on library provided threads and the both the wallet and the
     * listener objects are locked during dispatch, so your listeners do not have to be thread safe. However they
     * should not block as the Peer will be unresponsive to network traffic whilst your listener is running.
     */
    public synchronized void addEventListener(WalletEventListener listener) {
        eventListeners.add(listener);
    }

    /**
     * Call this when we have successfully transmitted the send tx to the network, to update the wallet.
     */
    synchronized void confirmSend(Transaction tx) {
        assert !pending.containsKey(tx) : "confirmSend called on the same transaction twice";
        // Mark each connected output of the tx as spent, so we don't try and spend it again.
        for (TransactionInput input : tx.inputs) {
            TransactionOutput connectedOutput = input.outpoint.getConnectedOutput();
            assert !connectedOutput.isSpent : "createSend called before corresponding confirmSend";
            connectedOutput.isSpent = true;
        }
        // Some of the outputs probably send coins back to us, eg for change or because this transaction is just
        // consolidating the wallet. Mark any output that is NOT back to us as spent. Then add this TX to the
        // pending pool.
        for (TransactionOutput output : tx.outputs) {
            if (!output.isMine(this)) {
                // This output didn't go to us, so by definition it is now spent.
                assert !output.isSpent;
                output.isSpent = true;
            }
        }
        pending.put(tx.getHash(), tx);
    }

    /**
     * Statelessly creates a transaction that sends the given number of nanocoins to address. The change is sent to
     * the first address in the wallet, so you must have added at least one key.<p>
     *
     * This method is stateless in the sense that calling it twice with the same inputs will result in two
     * Transaction objects which are equal. The wallet is not updated to track its pending status or to mark the
     * coins as spent until confirmSend is called on the result.
     */
    synchronized Transaction createSend(Address address,  BigInteger nanocoins) {
        // For now let's just pick the first key in our keychain. In future we might want to do something else to
        // give the user better privacy here, eg in incognito mode.
        assert keychain.size() > 0 : "Can't send value without an address to use for receiving change";
        ECKey first = keychain.get(0);
        return createSend(address, nanocoins, first.toAddress(params));
    }

    /**
     * Sends coins to the given address, via the given {@link Peer}. Change is returned to the first key in the wallet.
     * @param to Which address to send coins to.
     * @param nanocoins How many nanocoins to send. You can use Utils.toNanoCoins() to calculate this.
     * @return The {@link Transaction} that was created or null if there was insufficient balance to send the coins.
     * @throws IOException if there was a problem broadcasting the transaction
     */
    public synchronized Transaction sendCoins(Peer peer, Address to, BigInteger nanocoins) throws IOException {
        Transaction tx = createSend(to, nanocoins);
        if (tx == null)   // Not enough money! :-(
            return null;
        peer.broadcastTransaction(tx);
        confirmSend(tx);
        return tx;
    }

    /**
     * Creates a transaction that sends $coins.$cents BTC to the given address.<p>
     *
     * IMPORTANT: This method does NOT update the wallet. If you call createSend again you may get two transactions
     * that spend the same coins. You have to call confirmSend on the created transaction to prevent this,
     * but that should only occur once the transaction has been accepted by the network. This implies you cannot have
     * more than one outstanding sending tx at once.
     *
     * @param address The BitCoin address to send the money to.
     * @param nanocoins How much currency to send, in nanocoins.
     * @param changeAddress Which address to send the change to, in case we can't make exactly the right value from
     * our coins. This should be an address we own (is in the keychain).
     * @return a new {@link Transaction} or null if we cannot afford this send.
     */
    synchronized Transaction createSend(Address address, BigInteger nanocoins, Address changeAddress) {
        log.info("Creating send tx to " + address.toString() + " for " +
                bitcoinValueToFriendlyString(nanocoins));
        // To send money to somebody else, we need to do gather up transactions with unspent outputs until we have
        // sufficient value. Many coin selection algorithms are possible, we use a simple but suboptimal one.
        // TODO: Sort coins so we use the smallest first, to combat wallet fragmentation and reduce fees.
        BigInteger valueGathered = BigInteger.ZERO;
        List<TransactionOutput> gathered = new LinkedList<TransactionOutput>();
        for (Transaction tx : unspent.values()) {
            for (TransactionOutput output : tx.outputs) {
                if (output.isSpent) continue;
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
            return null;
        }
        assert gathered.size() > 0;
        Transaction sendTx = new Transaction(params);
        sendTx.addOutput(new TransactionOutput(params, nanocoins, address, sendTx));
        BigInteger change = valueGathered.subtract(nanocoins);
        if (change.compareTo(BigInteger.ZERO) > 0) {
            // The value of the inputs is greater than what we want to send. Just like in real life then,
            // we need to take back some coins ... this is called "change". Add another output that sends the change
            // back to us.
            log.info("  with " + bitcoinValueToFriendlyString(change) + " coins change");
            sendTx.addOutput(new TransactionOutput(params, change, changeAddress, sendTx));
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
        return sendTx;
    }

    /**
     * Adds the given ECKey to the wallet. There is currently no way to delete keys (that would result in coin loss).
     */
    public synchronized void addKey(ECKey key) {
        assert !keychain.contains(key);
        keychain.add(key);
    }

    /**
     * Locates a keypair from the keychain given the hash of the public key. This is needed when finding out which
     * key we need to use to redeem a transaction output.
     * @return ECKey object or null if no such key was found.
     */
    public synchronized ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        for (ECKey key : keychain) {
            if (Arrays.equals(key.getPubKeyHash(), pubkeyHash)) return key;
        }
        return null;
    }

    /** Returns true if this wallet contains a public key which hashes to the given hash. */
    public synchronized boolean isPubKeyHashMine(byte[] pubkeyHash) {
        return findKeyFromPubHash(pubkeyHash) != null;
    }

    /**
     * Locates a keypair from the keychain given the raw public key bytes.
     * @return ECKey or null if no such key was found.
     */
    public synchronized ECKey findKeyFromPubKey(byte[] pubkey) {
        for (ECKey key : keychain) {
            if (Arrays.equals(key.getPubKey(), pubkey)) return key;
        }
        return null;
    }

    /** Returns true if this wallet contains a keypair with the given public key. */
    public synchronized boolean isPubKeyMine(byte[] pubkey) {
        return findKeyFromPubKey(pubkey) != null;
    }

    /**
     * Returns the balance of this wallet by summing up all unspent outputs that were sent to us.
     */
    public synchronized BigInteger getBalance() {
        BigInteger balance = BigInteger.ZERO;
        for (Transaction tx : unspent.values()) {
            for (TransactionOutput output : tx.outputs) {
                if (output.isSpent) continue;
                if (!output.isMine(this)) continue;
                balance = balance.add(output.getValue());
            }
        }
        return balance;
    }

    @Override
    public synchronized String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Wallet containing ");
        builder.append(bitcoinValueToFriendlyString(getBalance()));
        builder.append("BTC in ");
        builder.append(unspent.size());
        builder.append(" unspent transactions/");
        builder.append(spent.size());
        builder.append(" spent transactions");
        // Do the keys.
        builder.append("\nKeys:\n");
        for (ECKey key : keychain) {
            builder.append("  addr:");
            builder.append(key.toAddress(params));
            builder.append(" ");
            builder.append(key.toString());
            builder.append("\n");
        }
        return builder.toString();
    }

    /**
     * Called by the {@link BlockChain} when the best chain (representing total work done) has changed. In this case,
     * we need to go through our transactions and find out if any have become invalid. It's possible for our balance
     * to go down in this case: money we thought we had can suddenly vanish if the rest of the network agrees it
     * should be so.
     */
    synchronized void reorganize(Set<StoredBlock> oldBlocks, Set<StoredBlock> newBlocks) throws VerificationException {
        // This runs on any peer thread with the block chain synchronized.
        //
        // The reorganize functionality of the wallet is tested in the BlockChainTest.testForking* methods.
        //
        // For each transaction we track which blocks they appeared in. Once a re-org takes place we have to find all
        // transactions in the old branch, all transactions in the new branch and find the difference of those sets.
        //
        // receive() has been called on the block that is triggering the re-org before this is called.
        Set<Transaction> oldChainTransactions = new HashSet<Transaction>();
        Set<Transaction> newChainTransactions = new HashSet<Transaction>();

        Set<Transaction> all = new HashSet<Transaction>();
        all.addAll(unspent.values());
        all.addAll(spent.values());
        all.addAll(inactive.values());
        for (Transaction tx : all) {
            Set<StoredBlock> appearsIn = tx.getAppearsIn();
            assert appearsIn != null;
            // If the set of blocks this transaction appears in is disjoint with one of the chain segments it means
            // the transaction was never incorporated by a miner into that side of the chain.
            if (!Collections.disjoint(appearsIn, oldBlocks)) {
                boolean alreadyPresent = !oldChainTransactions.add(tx);
                assert !alreadyPresent : "Transaction appears twice in chain segment";
            }
            if (!Collections.disjoint(appearsIn, newBlocks)) {
                boolean alreadyPresent = !newChainTransactions.add(tx);
                assert !alreadyPresent : "Transaction appears twice in chain segment";
            }
        }

        // If there is no difference it means we the user doesn't really care about this re-org but we still need to
        // update the transaction block pointers for next time.
        boolean affectedUs = !oldChainTransactions.equals(newChainTransactions);
        log.info(affectedUs ? "Re-org affected our transactions" : "Re-org had no effect on our transactions");
        if (!affectedUs) return;

        // Transactions that were in the old chain but aren't in the new chain. These will become inactive.
        Set<Transaction> gone = new HashSet<Transaction>(oldChainTransactions);
        gone.removeAll(newChainTransactions);
        // Transactions that are in the new chain but aren't in the old chain. These will be re-processed.
        Set<Transaction> fresh = new HashSet<Transaction>(newChainTransactions);
        fresh.removeAll(oldChainTransactions);
        assert !(gone.isEmpty() && fresh.isEmpty()) : "There must have been some changes to get here";

        for (Transaction tx : gone) {
            log.info("tx not in new chain: <-unspent/spent  ->inactive\n" + tx.toString());
            unspent.remove(tx.getHash());
            spent.remove(tx.getHash());
            inactive.put(tx.getHash(), tx);
            // We do not put it into the pending pool. Pending is for transactions we know are valid. After a re-org
            // some transactions may become permanently invalid if the new chain contains a double spend. We don't
            // want transactions sitting in the pending pool forever. This means shortly after a re-org the balance
            // might change rapidly as newly transactions are resurrected and included into the new chain by miners.
        }
        for (Transaction tx : fresh) {
            inactive.remove(tx.getHash());
            processTxFromBestChain(tx);
        }

        // Inform event listeners that a re-org took place.
        for (WalletEventListener l : eventListeners) {
            // Synchronize on the event listener as well. This allows a single listener to handle events from
            // multiple wallets without needing to worry about being thread safe.
            synchronized (l) {
                l.onReorganize();
            }
        }
    }

    /**
     * Returns an immutable view of the transactions currently waiting for network confirmations.
     */
    public Collection<Transaction> getPendingTransactions() {
        return Collections.unmodifiableCollection(pending.values());
    }
}
