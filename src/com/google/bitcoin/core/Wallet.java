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

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

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
    private static final long serialVersionUID = -4501424466753895784L;

    /**
     * A list of transactions with outputs we can spend. Note that some of these transactions may be partially spent,
     * that is, they have outputs some of which are redeemed and others which aren't already. The spentness of each
     * output is tracked in the TransactionOutput object. The value of all unspent outputs is the balance of the
     * wallet.
     */
    public final ArrayList<Transaction> unspent;

    /**
     * When all the outputs of a transaction are spent, it gets put here. These transactions aren't useful for
     * anything except record keeping and presentation to the user.
     */
    final LinkedList<Transaction> fullySpent;

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
        unspent = new ArrayList<Transaction>();
        fullySpent = new LinkedList<Transaction>();
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
    static public Wallet loadFromFile(File f) throws IOException {
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
        for (Transaction tx : unspent) {
            if (Arrays.equals(tx.getHash(), transaction.getHash())) return true;
        }
        for (Transaction tx : fullySpent) {
            if (Arrays.equals(tx.getHash(), transaction.getHash())) return true;
        }
        return false;
    }

    /**
     * Called by the {@link BlockChain} when we receive a new block that sends coins to one of our addresses,
     * stores the transaction in the wallet so we can spend it in future. Don't call this on transactions we already
     * have, for instance because we created them ourselves!
     */
    synchronized void receive(Transaction tx) throws VerificationException {
        // Runs in a peer thread.
        BigInteger prevBalance = getBalance();

        // We need to check if this transaction is spending one of our own previous transactions. This allows us to
        // build up a record of our balance by reading the block chain from scratch. Other than making testing easier
        // this will be useful if one day we want to support importing keypairs from a wallet.db
        for (TransactionInput input : tx.inputs) {
            for (int i = 0; i < unspent.size(); i++) {
                Transaction t = unspent.get(i);
                if (!Arrays.equals(input.outpoint.hash, t.getHash())) continue;
                if (input.outpoint.index > t.outputs.size()) {
                    throw new VerificationException("Invalid tx connection for " +
                            Utils.bytesToHexString(tx.getHash()));
                }
                TransactionOutput linkedOutput = t.outputs.get((int) input.outpoint.index);
                assert !linkedOutput.isSpent : "Double spend was accepted by network?";
                Utils.LOG("Saw a record of me spending " + Utils.bitcoinValueToFriendlyString(linkedOutput.getValue())
                        + " BTC");
                linkedOutput.isSpent = true;
                // Are all the outputs on this TX that are mine now spent? Note that some of the outputs may not
                // be mine and thus we don't care about them.
                int myOutputs = 0;
                int mySpentOutputs = 0;
                for (TransactionOutput output : t.outputs) {
                    if (!output.isMine(this)) continue;
                    myOutputs++;
                    if (output.isSpent)
                        mySpentOutputs++;
                }
                if (myOutputs == mySpentOutputs) {
                    // All the outputs we can claim on this TX are gone now. So remove it from the unspent list
                    // so future transaction processing is faster.
                    unspent.remove(i);
                    i--;  // Adjust the counter so we are still in the right place after removal.
                    // Keep around a record of the now useless TX in case we need it in future.
                    fullySpent.add(t);
                }
            }
        }
        Utils.LOG("Received " + Utils.bitcoinValueToFriendlyString(tx.getValueSentToMe(this)));
        unspent.add(tx);
        Utils.LOG("Balance is now: " + Utils.bitcoinValueToFriendlyString(getBalance()));

        // Inform anyone interested that we have new coins. Note: we may be re-entered by the event listener,
        // so we must not make assumptions about our state after this loop returns! For example,
        // the balance we just received might already be spent!
        for (WalletEventListener l : eventListeners) {
            synchronized (l) {
                l.onCoinsReceived(this, tx, prevBalance, getBalance());
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
        // This tx is supposed to be fresh, it's an error to confirmSend on a transaction that was already sent.
        assert !unspent.contains(tx);
        assert !fullySpent.contains(tx);
        // Mark each connected output of the tx as spent, so we don't try and spend it again.
        for (TransactionInput input : tx.inputs) {
            TransactionOutput connectedOutput = input.outpoint.getConnectedOutput();
            assert !connectedOutput.isSpent : "createSend called before corresponding confirmSend";
            connectedOutput.isSpent = true;
        }
        // Some of the outputs probably send coins back to us, eg for change or because this transaction is just
        // consolidating the wallet. Mark any output that is NOT back to us as spent,
        // then add this TX to the wallet so we can show it in the UI later and use it for further spending.
        try {
            int numSpentOutputs = 0;
            for (TransactionOutput output : tx.outputs) {
                if (findKeyFromPubHash(output.getScriptPubKey().getToAddress().getHash160()) == null) {
                    // This output didn't go to us, so by definition it is now spent.
                    assert !output.isSpent;
                    output.isSpent = true;
                    numSpentOutputs++;
                }
            }
            if (numSpentOutputs == tx.outputs.size()) {
                // All of the outputs are to other people, so this transaction isn't useful anymore for further
                // spending. Stick it in a different section of the wallet so it doesn't slow down creating future
                // spend transactions.
                fullySpent.add(tx);
            } else {
                unspent.add(tx);
            }
        } catch (ScriptException e) {
            // This cannot happen - we made this script so we should be able to parse it.
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates a transaction that sends the given number of nanocoins to address. The change is sent to the first
     * address in the wallet, so you must have added at least one key.
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
    synchronized Transaction createSend(Address address,  BigInteger nanocoins, Address changeAddress) {
        Utils.LOG("Creating send tx to " + address.toString() + " for " +
                Utils.bitcoinValueToFriendlyString(nanocoins));
        // To send money to somebody else, we need to do the following:
        //  - Gather up transactions with unspent outputs until we have sufficient value.
        // TODO: Sort coins so we use the smallest first, to combat wallet fragmentation.
        BigInteger valueGathered = BigInteger.ZERO;
        List<TransactionOutput> gathered = new LinkedList<TransactionOutput>();
        for (Transaction tx : unspent) {
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
            Utils.LOG("Insufficient value in wallet for send, missing " +
                    Utils.bitcoinValueToFriendlyString(nanocoins.subtract(valueGathered)));
            // TODO: Should throw an exception here.
            return null;
        }
        Transaction sendTx = new Transaction(params);
        sendTx.addOutput(new TransactionOutput(params, nanocoins, address));
        BigInteger change = valueGathered.subtract(nanocoins);
        if (change.compareTo(BigInteger.ZERO) > 0) {
            // The value of the inputs is greater than what we want to send. Just like in real life then,
            // we need to take back some coins ... this is called "change". Add another output that sends the change
            // back to us.
            Utils.LOG("  with " + Utils.bitcoinValueToFriendlyString(change) + " coins change");
            sendTx.addOutput(new TransactionOutput(params, change, changeAddress));
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

    /**
     * Returns the balance of this wallet in nanocoins by summing up all unspent outputs that were sent to us.
     */
    public synchronized BigInteger getBalance() {
        BigInteger balance = BigInteger.ZERO;
        for (Transaction tx : unspent) {
            for (TransactionOutput output : tx.outputs) {
                if (output.isSpent) continue;
                if (!output.isMine(this)) continue;
                balance = balance.add(output.getValue());
            }
        }
        return balance;
    }
}
