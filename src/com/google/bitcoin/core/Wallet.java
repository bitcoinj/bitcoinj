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
 * providing transactions on demand that meet a given combined value.<p>
 *
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
     * are waiting for a miner to send a block on the best chain including them. These transactions inputs count as
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

    /**
     * A dead transaction is one that's been overridden by a double spend. Such a transaction is pending except it
     * will never confirm and so should be presented to the user in some unique way - flashing red for example. This
     * should nearly never happen in normal usage. Dead transactions can be "resurrected" by re-orgs just like any
     * other. Dead transactions are not in the pending pool.
     */
    private Map<Sha256Hash, Transaction> dead;

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
        dead = new HashMap<Sha256Hash, Transaction>();
        eventListeners = new ArrayList<WalletEventListener>();
    }

    /**
     * Uses Java serialization to save the wallet to the given file.
     */
    public synchronized void saveToFile(File f) throws IOException {
        saveToFileStream(new FileOutputStream(f));
    }

    /**
     * Uses Java serialization to save the wallet to the given file stream.
     */
    public synchronized void saveToFileStream(FileOutputStream f) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(f);
        oos.writeObject(this);
        oos.close();
    }


    /**
     * Returns a wallet deserialized from the given file.
     */
    public static Wallet loadFromFile(File f) throws IOException {
        return loadFromFileStream(new FileInputStream(f));
    }

    /**
     * Returns a wallet deserialied from the given file input stream.
     */
    public static Wallet loadFromFileStream(FileInputStream f) throws IOException {
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(f);
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
        receive(tx, block, blockType, false);
    }

    private synchronized void receive(Transaction tx, StoredBlock block,
                                      BlockChain.NewBlockType blockType, boolean reorg) throws VerificationException, ScriptException {
        // Runs in a peer thread.
        BigInteger prevBalance = getBalance();

        Sha256Hash txHash = tx.getHash();

        boolean bestChain = blockType == BlockChain.NewBlockType.BEST_CHAIN;
        boolean sideChain = blockType == BlockChain.NewBlockType.SIDE_CHAIN;

        BigInteger valueSentFromMe = tx.getValueSentFromMe(this);
        BigInteger valueSentToMe = tx.getValueSentToMe(this);
        BigInteger valueDifference = valueSentToMe.subtract(valueSentFromMe);

        if (!reorg) {
            log.info("Received tx{} for {} BTC: {}", new Object[] { sideChain ? " on a side chain" : "",
                    bitcoinValueToFriendlyString(valueDifference), tx.getHashAsString()});
        }

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
            if (!reorg) {
                // Mark the tx as appearing in this block so we can find it later after a re-org.
                tx.addBlockAppearance(block);
            }
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
        if (!reorg && bestChain && valueDifference.compareTo(BigInteger.ZERO) > 0) {
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
            log.info("  new tx ->unspent");
            boolean alreadyPresent = unspent.put(tx.getHash(), tx) != null;
            assert !alreadyPresent : "TX was received twice";
        } else {
            // It spent some of our coins and did not send us any.
            log.info("  new tx ->spent");
            boolean alreadyPresent = spent.put(tx.getHash(), tx) != null;
            assert !alreadyPresent : "TX was received twice";
        }
    }

    /**
     * Updates the wallet by checking if this TX spends any of our outputs. This is not used normally because
     * when we receive our own spends, we've already marked the outputs as spent previously (during tx creation) so
     * there's no need to go through and do it again.
     */
    private void updateForSpends(Transaction tx) throws VerificationException {
        for (TransactionInput input : tx.inputs) {
            TransactionInput.ConnectionResult result = input.connect(unspent, false);
            if (result == TransactionInput.ConnectionResult.NO_SUCH_TX) {
                // Doesn't spend any of our outputs or is coinbase.
                continue;
            } else if (result == TransactionInput.ConnectionResult.ALREADY_SPENT) {
                // Double spend! This must have overridden a pending tx, or the block is bad (contains transactions
                // that illegally double spend: should never occur if we are connected to an honest node).
                //
                // Work backwards like so:
                //
                //   A  -> spent by B [pending]
                //     \-> spent by C [chain]
                Transaction doubleSpent = input.outpoint.fromTx;   // == A
                Transaction connected = doubleSpent.outputs.get((int)input.outpoint.index).getSpentBy().parentTransaction;
                if (pending.containsKey(connected.getHash())) {
                    log.info("Saw double spend from chain override pending tx {}", connected.getHashAsString());
                    log.info("  <-pending ->dead");
                    pending.remove(connected.getHash());
                    dead.put(connected.getHash(), connected);
                    // Now forcibly change the connection.
                    input.connect(unspent, true);
                    // Inform the event listeners of the newly dead tx.
                    for (WalletEventListener listener : eventListeners) {
                        synchronized (listener) {
                            listener.onDeadTransaction(connected, tx);
                        }
                    }
                }
            } else if (result == TransactionInput.ConnectionResult.SUCCESS) {
                // Otherwise we saw a transaction spend our coins, but we didn't try and spend them ourselves yet.
                // The outputs are already marked as spent by the connect call above, so check if there are any more for
                // us to use. Move if not.
                Transaction connected = input.outpoint.fromTx;
                if (connected.getValueSentToMe(this, false).equals(BigInteger.ZERO)) {
                    // There's nothing left I can spend in this transaction.
                    if (unspent.remove(connected.getHash()) != null) {
                        log.info("  prevtx <-unspent");
                        log.info("  prevtx ->spent");
                        spent.put(connected.getHash(), connected);
                    }
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
        assert !pending.containsKey(tx.getHash()) : "confirmSend called on the same transaction twice";
        log.info("confirmSend of {}", tx.getHashAsString());
        // Mark the outputs of the used transcations as spent, so we don't try and spend it again.
        for (TransactionInput input : tx.inputs) {
            TransactionOutput connectedOutput = input.outpoint.getConnectedOutput();
            connectedOutput.markAsSpent(input);
        }
        // Some of the outputs probably send coins back to us, eg for change or because this transaction is just
        // consolidating the wallet. Mark any output that is NOT back to us as spent. Then add this TX to the
        // pending pool.
        for (TransactionOutput output : tx.outputs) {
            if (!output.isMine(this)) {
                // This output didn't go to us, so by definition it is now spent.
                output.markAsSpent(null);
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
            return null;
        }
        assert gathered.size() > 0;
        Transaction sendTx = new Transaction(params);
        sendTx.addOutput(new TransactionOutput(params, sendTx, nanocoins, address));
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
        log.info("  created {}", sendTx.getHashAsString());
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
     * It's possible to calculate a wallets balance from multiple points of view. This enum selects which
     * getBalance() should use.<p>
     *
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
    };

    /**
     * Returns the AVAILABLE balance of this wallet. See {@link BalanceType#AVAILABLE} for details on what this
     * means.<p>
     *
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
            for (TransactionOutput output : tx.outputs) {
                if (!output.isMine(this)) continue;
                if (!output.isAvailableForSpending()) continue;
                available = available.add(output.getValue());
            }
        }
        if (balanceType == BalanceType.AVAILABLE)
            return available;
        assert balanceType == BalanceType.ESTIMATED;
        // Now add back all the pending outputs to assume the transaction goes through.
        BigInteger estimated = available;
        for (Transaction tx : pending.values()) {
            for (TransactionOutput output : tx.outputs) {
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
            for (Transaction tx : unspent.values()) builder.append(tx);
        }
        if (spent.size() > 0) {
            builder.append("\nSPENT:\n");
            for (Transaction tx : spent.values()) builder.append(tx);
        }
        if (pending.size() > 0) {
            builder.append("\nPENDING:\n");
            for (Transaction tx : pending.values()) builder.append(tx);
        }
        if (inactive.size() > 0) {
            builder.append("\nINACTIVE:\n");
            for (Transaction tx : inactive.values()) builder.append(tx);
        }
        if (dead.size() > 0) {
            builder.append("\nDEAD:\n");
            for (Transaction tx : dead.values()) builder.append(tx);
        }
        return builder.toString();
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

        log.info("  Old part of chain (top to bottom):");
        for (StoredBlock b : oldBlocks) log.info("    {}", b.getHeader().getHashAsString());
        log.info("  New part of chain (top to bottom):");
        for (StoredBlock b : newBlocks) log.info("    {}", b.getHeader().getHashAsString());

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
            Set<StoredBlock> appearsIn = tx.getAppearsIn();
            assert appearsIn != null;
            // If the set of blocks this transaction appears in is disjoint with one of the chain segments it means
            // the transaction was never incorporated by a miner into that side of the chain.
            boolean inOldSection = !Collections.disjoint(appearsIn, oldBlocks);
            boolean inNewSection = !Collections.disjoint(appearsIn, newBlocks);
            boolean inCommonSection = !inNewSection && !inOldSection;

            if (inCommonSection) {
                boolean alreadyPresent = commonChainTransactions.put(tx.getHash(), tx) != null;
                assert !alreadyPresent : "Transaction appears twice in common chain segment";
            } else {
                if (inOldSection) {
                    boolean alreadyPresent = oldChainTransactions.put(tx.getHash(), tx) != null;
                    assert !alreadyPresent : "Transaction appears twice in old chain segment";
                    if (!inNewSection) {
                        alreadyPresent = onlyOldChainTransactions.put(tx.getHash(), tx) != null;
                        assert !alreadyPresent : "Transaction appears twice in only-old map";
                    }
                }
                if (inNewSection) {
                    boolean alreadyPresent = newChainTransactions.put(tx.getHash(), tx) != null;
                    assert !alreadyPresent : "Transaction appears twice in new chain segment";
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
            TransactionInput badInput = tx.connectInputs(all, false);
            assert badInput == null : "Failed to connect " + tx.getHashAsString() + ", " + badInput.toString();
        }
        // Recalculate the unspent/spent buckets for the transactions the re-org did not affect.
        unspent.clear();
        spent.clear();
        inactive.clear();
        for (Transaction tx : commonChainTransactions.values()) {
            int unspentOutputs = 0;
            for (TransactionOutput output : tx.outputs) {
                if (output.isAvailableForSpending()) unspentOutputs++;
            }
            if (unspentOutputs > 0) {
                log.info("  TX {}: ->unspent", tx.getHashAsString());
                unspent.put(tx.getHash(), tx);
            } else {
                log.info("  TX {}: ->spent", tx.getHashAsString());
                spent.put(tx.getHash(), tx);
            }
        }
        // Now replay the act of receiving the blocks that were previously in a side chain. This will:
        //   - Move any transactions that were pending and are now accepted into the right bucket.
        //   - Connect the newly active transactions.
        Collections.reverse(newBlocks);  // Need bottom-to-top but we get top-to-bottom.
        for (StoredBlock b : newBlocks) {
            log.info("Replaying block {}", b.getHeader().getHashAsString());
            Set<Transaction> txns = new HashSet<Transaction>();
            for (Transaction tx : newChainTransactions.values()) {
                if (tx.appearsIn.contains(b)) {
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
        log.info("Reprocessing:");
        // Note, we must reprocess dead transactions first. The reason is that if there is a double spend across
        // chains from our own coins we get a complicated situation:
        //
        // 1) We switch to a new chain (B) that contains a double spend overriding a pending transaction. It goes dead.
        // 2) We switch BACK to the first chain (A). The dead transaction must go pending again.
        // 3) We resurrect the transactions that were in chain (B) and assume the miners will start work on putting them
        //    in to the chain, but it's not possible because it's a double spend. So now that transaction must become
        //    dead instead of pending.
        //
        // This only occurs when we are double spending our own coins.
        for (Transaction tx : dead.values()) {
            reprocessTxAfterReorg(pool, tx);
        }
        for (Transaction tx : toReprocess.values()) {
            reprocessTxAfterReorg(pool, tx);
        }

        log.info("post-reorg balance is {}", Utils.bitcoinValueToFriendlyString(getBalance()));

        // Inform event listeners that a re-org took place.
        for (WalletEventListener l : eventListeners) {
            // Synchronize on the event listener as well. This allows a single listener to handle events from
            // multiple wallets without needing to worry about being thread safe.
            synchronized (l) {
                l.onReorganize();
            }
        }
    }

    private void reprocessTxAfterReorg(Map<Sha256Hash, Transaction> pool, Transaction tx) {
        log.info("  TX {}", tx.getHashAsString());
        int numInputs = tx.inputs.size();
        int noSuchTx = 0;
        int success = 0;
        boolean isDead = false;
        for (TransactionInput input : tx.inputs) {
            if (input.isCoinBase()) {
                // Input is not in our wallet so there is "no such input tx", bit of an abuse.
                noSuchTx++;
                continue;
            }
            TransactionInput.ConnectionResult result = input.connect(pool, false);
            if (result == TransactionInput.ConnectionResult.SUCCESS) {
                success++;
            } else if (result == TransactionInput.ConnectionResult.NO_SUCH_TX) {
                noSuchTx++;
            } else if (result == TransactionInput.ConnectionResult.ALREADY_SPENT) {
                isDead = true;
                // This transaction was replaced by a double spend on the new chain. Did you just reverse
                // your own transaction? I hope not!!
                log.info("   ->dead, will not confirm now unless there's another re-org", tx.getHashAsString());
                TransactionOutput doubleSpent = input.getConnectedOutput(pool);
                Transaction replacement = doubleSpent.getSpentBy().parentTransaction;
                dead.put(tx.getHash(), tx);
                // Inform the event listeners of the newly dead tx.
                for (WalletEventListener listener : eventListeners) {
                    synchronized (listener) {
                        listener.onDeadTransaction(tx, replacement);
                    }
                }
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
        }
    }

    /**
     * Returns an immutable view of the transactions currently waiting for network confirmations.
     */
    public Collection<Transaction> getPendingTransactions() {
        return Collections.unmodifiableCollection(pending.values());
    }
}
