package org.bitcoinj.wallet;

import com.google.common.annotations.VisibleForTesting;
import org.bitcoinj.base.*;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.base.internal.StreamUtils;
import org.bitcoinj.core.*;
import org.bitcoinj.core.listeners.NewBestBlockListener;
import org.bitcoinj.core.listeners.ReorganizeListener;
import org.bitcoinj.core.listeners.TransactionConfidenceEventListener;
import org.bitcoinj.core.listeners.TransactionReceivedInBlockListener;
import org.bitcoinj.crypto.*;
import org.bitcoinj.protobuf.wallet.Protos;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.listeners.*;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

 public interface WalletService extends NewBestBlockListener, TransactionReceivedInBlockListener, PeerFilterProvider,
        KeyBag, TransactionBag, ReorganizeListener, AddressParser{


    void createTransientState();

     Network network();

    /**
     * Parse an address string using all formats this wallet knows about for the wallet's network type
     * @param addressString Address string to parse
     * @return A validated address
     * @throws AddressFormatException if invalid string
     */
    Address parseAddress(String addressString);

    /**
     * Gets the active keychains via {@link KeyChainGroup#getActiveKeyChains(Instant)}.
     */
    List<DeterministicKeyChain> getActiveKeyChains();

    /**
     * Gets the default active keychain via {@link KeyChainGroup#getActiveKeyChain()}.
     */
    DeterministicKeyChain getActiveKeyChain();

    /**
     * <p>Adds given transaction signer to the list of signers. It will be added to the end of the signers list, so if
     * this wallet already has some signers added, given signer will be executed after all of them.</p>
     * <p>Transaction signer should be fully initialized before adding to the wallet, otherwise {@link IllegalStateException}
     * will be thrown</p>
     */
    void addTransactionSigner(TransactionSigner signer);

    List<TransactionSigner> getTransactionSigners();

    // ***************************************************************************************************************

    //region Key Management

    /**
     * Returns a key that hasn't been seen in a transaction yet, and which is suitable for displaying in a wallet
     * user interface as "a convenient key to receive funds on" when the purpose parameter is
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS}. The returned key is stable until
     * it's actually seen in a pending or confirmed transaction, at which point this method will start returning
     * a different key (for each purpose independently).
     */
     DeterministicKey currentKey(KeyChain.KeyPurpose purpose);

    /**
     * An alias for calling {@link #currentKey(KeyChain.KeyPurpose)} with
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS} as the parameter.
     */
     DeterministicKey currentReceiveKey();
    /**
     * Returns address for a {@link #currentKey(KeyChain.KeyPurpose)}
     */
     Address currentAddress(KeyChain.KeyPurpose purpose);

    /**
     * An alias for calling {@link #currentAddress(KeyChain.KeyPurpose)} with
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS} as the parameter.
     */
     Address currentReceiveAddress();

    /**
     * Returns a key that has not been returned by this method before (fresh). You can think of this as being
     * a newly created key, although the notion of "create" is not really valid for a
     * {@link DeterministicKeyChain}. When the parameter is
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key out
     * to someone who wishes to send money.
     */
     DeterministicKey freshKey(KeyChain.KeyPurpose purpose);

    /**
     * Returns a key/s that has not been returned by this method before (fresh). You can think of this as being
     * a newly created key/s, although the notion of "create" is not really valid for a
     * {@link DeterministicKeyChain}. When the parameter is
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS} the returned key is suitable for being put
     * into a receive coins wizard type UI. You should use this when the user is definitely going to hand this key/s out
     * to someone who wishes to send money.
     */
     List<DeterministicKey> freshKeys(KeyChain.KeyPurpose purpose, int numberOfKeys);

    /**
     * An alias for calling {@link #freshKey(KeyChain.KeyPurpose)} with
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS} as the parameter.
     */
     DeterministicKey freshReceiveKey();

    /**
     * Returns address for a {@link #freshKey(KeyChain.KeyPurpose)}
     */
     Address freshAddress(KeyChain.KeyPurpose purpose);

    /**
     * An alias for calling {@link #freshAddress(KeyChain.KeyPurpose)} with
     * {@link KeyChain.KeyPurpose#RECEIVE_FUNDS} as the parameter.
     */
     Address freshReceiveAddress();

    /**
     * <p>Returns a fresh receive address for a given {@link ScriptType}.</p>
     * <p>This method is meant for when you really need a fallback address. Normally, you should be
     * using {@link #freshAddress(KeyChain.KeyPurpose)} or
     * {@link #currentAddress(KeyChain.KeyPurpose)}.</p>
     */
    Address freshReceiveAddress(ScriptType scriptType);

    /**
     * Returns only the keys that have been issued by {@link #freshReceiveKey()}, {@link #freshReceiveAddress()},
     * {@link #currentReceiveKey()} or {@link #currentReceiveAddress()}.
     */
    List<ECKey> getIssuedReceiveKeys();

    /**
     * Returns only the addresses that have been issued by {@link #freshReceiveKey()}, {@link #freshReceiveAddress()},
     * {@link #currentReceiveKey()} or {@link #currentReceiveAddress()}.
     */
     List<Address> getIssuedReceiveAddresses();

    /**
     * Upgrades the wallet to be deterministic (BIP32). You should call this, possibly providing the users encryption
     * key, after loading a wallet produced by previous versions of bitcoinj. If the wallet is encrypted the key
     * <b>must</b> be provided, due to the way the seed is derived deterministically from private key bytes: failing
     * to do this will result in an exception being thrown. For non-encrypted wallets, the upgrade will be done for
     * you automatically the first time a new key is requested (this happens when spending due to the change address).
     */
     void upgradeToDeterministic(ScriptType outputScriptType, @Nullable AesKey aesKey)
            throws DeterministicUpgradeRequiresPassword;

    /**
     * Upgrades the wallet to be deterministic (BIP32). You should call this, possibly providing the users encryption
     * key, after loading a wallet produced by previous versions of bitcoinj. If the wallet is encrypted the key
     * <b>must</b> be provided, due to the way the seed is derived deterministically from private key bytes: failing
     * to do this will result in an exception being thrown. For non-encrypted wallets, the upgrade will be done for
     * you automatically the first time a new key is requested (this happens when spending due to the change address).
     */
     void upgradeToDeterministic(ScriptType outputScriptType, KeyChainGroupStructure structure,
                                       @Nullable AesKey aesKey) throws DeterministicUpgradeRequiresPassword;

    /**
     * Returns true if the wallet contains random keys and no HD chains, in which case you should call
     * {@link #upgradeToDeterministic(ScriptType, AesKey)} before attempting to do anything
     * that would require a new address or key.
     */
     boolean isDeterministicUpgradeRequired(ScriptType outputScriptType);

    /**
     * Returns a snapshot of the watched scripts. This view is not live.
     */
     List<Script> getWatchedScripts();

    /**
     * Removes the given key from the basicKeyChain. Be very careful with this - losing a private key <b>destroys the
     * money associated with it</b>.
     * @return Whether the key was removed or not.
     */
     boolean removeKey(ECKey key);

    /**
     * Returns the number of keys in the key chain group, including lookahead keys.
     */
     int getKeyChainGroupSize();

    @VisibleForTesting
     int getKeyChainGroupCombinedKeyLookaheadEpochs();

    /**
     * Returns a list of the non-deterministic keys that have been imported into the wallet, or the empty list if none.
     */
     List<ECKey> getImportedKeys();

    /** Returns the address used for change outputs. Note: this will probably go away in future. */
     Address currentChangeAddress();

    /**
     * <p>Imports the given ECKey to the wallet.</p>
     *
     * <p>If the wallet is configured to auto save to a file, triggers a save immediately. Runs the onKeysAdded event
     * handler. If the key already exists in the wallet, does nothing and returns false.</p>
     */
     boolean importKey(ECKey key);

    /**
     * Imports the given keys to the wallet.
     * If {@link Wallet#autosaveToFile(File, Duration, WalletFiles.Listener)}
     * has been called, triggers an auto save bypassing the normal coalescing delay and event handlers.
     * Returns the number of keys added, after duplicates are ignored. The onKeyAdded event will be called for each key
     * in the list that was not already present.
     */
     int importKeys(final List<ECKey> keys);

    void checkNoDeterministicKeys(List<ECKey> keys);

    /** Takes a list of keys and a password, then encrypts and imports them in one step using the current keycrypter. */
     int importKeysAndEncrypt(final List<ECKey> keys, CharSequence password);

    /** Takes a list of keys and an AES key, then encrypts and imports them in one step using the current keycrypter. */
     int importKeysAndEncrypt(final List<ECKey> keys, AesKey aesKey);

    /**
     * Add a pre-configured keychain to the wallet.  Useful for setting up a complex keychain,
     * such as for a married wallet (which is not supported any more).
     */
    void addAndActivateHDChain(DeterministicKeyChain chain);

    /** See {@link DeterministicKeyChain#setLookaheadSize(int)} for more info on this. */
     int getKeyChainGroupLookaheadSize();

    /** See {@link DeterministicKeyChain#setLookaheadThreshold(int)} for more info on this. */
     int getKeyChainGroupLookaheadThreshold();

    /**
     * Returns a -only DeterministicKey that can be used to set up a watching wallet: that is, a wallet that
     * can import transactions from the block chain just as the normal wallet can, but which cannot spend. Watching
     * wallets are very useful for things like web servers that accept payments. This key corresponds to the account
     * zero key in the recommended BIP32 hierarchy.
     */
     DeterministicKey getWatchingKey();

    /**
     * Returns whether this wallet consists entirely of watching keys (unencrypted keys with no private part). Mixed
     * wallets are forbidden.
     *
     * @throws IllegalStateException
     *             if there are no keys, or if there is a mix between watching and non-watching keys.
     */
     boolean isWatching();

    /**
     * Return true if we are watching this address.
     */
     boolean isAddressWatched(Address address);

    /**
     * Same as {@link #addWatchedAddress(Address, Instant)} with the current time as the creation time.
     */
     boolean addWatchedAddress(final Address address) ;

    /**
     * Adds the given address to the wallet to be watched. Outputs can be retrieved by {@link #getWatchedOutputs(boolean)}.
     *
     * @param creationTime creation time, for scanning the blockchain
     * @return whether the address was added successfully (not already present)
     */
     boolean addWatchedAddress(final Address address, Instant creationTime) ;

    /**
     * Adds the given addresses to the wallet to be watched. Outputs can be retrieved
     * by {@link #getWatchedOutputs(boolean)}.
     * @param addresses addresses to be watched
     * @param creationTime creation time of the addresses
     * @return how many addresses were added successfully
     */
     int addWatchedAddresses(final List<Address> addresses, Instant creationTime);

    /**
     * Returns all the outputs that match addresses or scripts added via {@link #addWatchedAddress(Address)} or
     * {@link #addWatchedScripts(java.util.List)}.
     * @param excludeImmatureCoinbases Whether to ignore outputs that are unspendable due to being immature.
     */
     List<TransactionOutput> getWatchedOutputs(boolean excludeImmatureCoinbases);

    /**
     * Adds the given addresses to the wallet to be watched. Outputs can be retrieved
     * by {@link #getWatchedOutputs(boolean)}. Use this if the creation time of the addresses is unknown.
     * @param addresses addresses to be watched
     * @return how many addresses were added successfully
     */
     int addWatchedAddresses(final List<Address> addresses);

    /**
     * Adds the given output scripts to the wallet to be watched. Outputs can be retrieved by {@link #getWatchedOutputs(boolean)}.
     * If a script is already being watched, the object is replaced with the one in the given list. As {@link Script}
     * equality is defined in terms of program bytes only this lets you update metadata such as creation time. Note that
     * you should be careful not to add scripts with a creation time of zero (the default!) because otherwise it will
     * disable the important wallet checkpointing optimisation.
     *
     * @return how many scripts were added successfully
     */
     int addWatchedScripts(final List<Script> scripts);
    /**
     * Removes the given output scripts from the wallet that were being watched.
     *
     * @return true if successful
     */
     boolean removeWatchedAddress(final Address address) ;

    /**
     * Removes the given output scripts from the wallet that were being watched.
     *
     * @return true if successful
     */
     boolean removeWatchedAddresses(final List<Address> addresses);

    /**
     * Removes the given output scripts from the wallet that were being watched.
     *
     * @return true if successful
     */
     boolean removeWatchedScripts(final List<Script> scripts);

    /**
     * Returns all addresses watched by this wallet.
     */
     List<Address> getWatchedAddresses() ;

    /**
     * Locates a keypair from the basicKeyChain given the hash of the  key. This is needed when finding out which
     * key we need to use to redeem a transaction output.
     *
     * @return ECKey object or null if no such key was found.
     */
    @Override
    @Nullable
     ECKey findKeyFromPubKeyHash(byte[] pubKeyHash, @Nullable ScriptType scriptType);

    /** Returns true if the given key is in the wallet, false otherwise. Currently an O(N) operation. */
     boolean hasKey(ECKey key);

    /**
     * Returns true if the address is belongs to this wallet.
     */
     boolean isAddressMine(Address address);

    @Override
     boolean isPubKeyHashMine(byte[] pubKeyHash, @Nullable ScriptType scriptType);

    @Override
     boolean isWatchedScript(Script script);

    /**
     * Locates a keypair from the wallet given the corresponding address.
     * @return ECKey or null if no such key was found.
     */
     ECKey findKeyFromAddress(Address address) ;
    /**
     * Locates a keypair from the basicKeyChain given the raw  key bytes.
     * @return ECKey or null if no such key was found.
     */
    @Override
    @Nullable
     ECKey findKeyFromPubKey(byte[] pubKey);

    @Override
     boolean isPubKeyMine(byte[] pubKey);

    /**
     * Locates a redeem data (redeem script and keys) from the keyChainGroup given the hash of the script.
     * Returns RedeemData object or null if no such data was found.
     */
    @Nullable
    @Override
     RedeemData findRedeemDataFromScriptHash(byte[] payToScriptHash) ;

    @Override
     boolean isPayToScriptHashMine(byte[] payToScriptHash);

    /**
     * Marks all keys used in the transaction output as used in the wallet.
     * See {@link DeterministicKeyChain#markKeyAsUsed(DeterministicKey)} for more info on this.
     */
    void markKeysAsUsed(Transaction tx);

    /**
     * Returns the immutable seed for the current active HD chain.
     * @throws ECKey.MissingPrivateKeyException if the seed is unavailable (watching wallet)
     */
     DeterministicSeed getKeyChainSeed();

    /**
     * Returns a key for the given HD path, assuming it's already been derived. You normally shouldn't use this:
     * use currentReceiveKey/freshReceiveKey instead.
     */
     DeterministicKey getKeyByPath(List<ChildNumber> path);

    /**
     * Convenience wrapper around {@link Wallet#encrypt(KeyCrypter,
     * AesKey)} which uses the default Scrypt key derivation algorithm and
     * parameters to derive a key from the given password.
     */
     void encrypt(CharSequence password);

    /**
     * Encrypt the wallet using the KeyCrypter and the AES key. A good default KeyCrypter to use is
     * {@link KeyCrypterScrypt}.
     *
     * @param keyCrypter The KeyCrypter that specifies how to encrypt/ decrypt a key
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming to create from a password)
     * @throws KeyCrypterException Thrown if the wallet encryption fails. If so, the wallet state is unchanged.
     */
     void encrypt(KeyCrypter keyCrypter, AesKey aesKey);

    /**
     * Decrypt the wallet with the wallets keyCrypter and password.
     * @throws Wallet.BadWalletEncryptionKeyException Thrown if the given password is wrong. If so, the wallet state is unchanged.
     * @throws KeyCrypterException Thrown if the wallet decryption fails. If so, the wallet state is unchanged.
     */
     void decrypt(CharSequence password);

    /**
     * Decrypt the wallet with the wallets keyCrypter and AES key.
     *
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming to create from a password)
     * @throws Wallet.BadWalletEncryptionKeyException Thrown if the given aesKey is wrong. If so, the wallet state is unchanged.
     * @throws KeyCrypterException Thrown if the wallet decryption fails. If so, the wallet state is unchanged.
     */
     void decrypt(AesKey aesKey) throws Wallet.BadWalletEncryptionKeyException;

    /**
     *  Check whether the password can decrypt the first key in the wallet.
     *  This can be used to check the validity of an entered password.
     *
     *  @return boolean true if password supplied can decrypt the first private key in the wallet, false otherwise.
     *  @throws IllegalStateException if the wallet is not encrypted.
     */
     boolean checkPassword(CharSequence password);

    /**
     *  Check whether the AES key can decrypt the first encrypted key in the wallet.
     *
     *  @return boolean true if AES key supplied can decrypt the first encrypted private key in the wallet, false otherwise.
     */
     boolean checkAESKey(AesKey aesKey);

    /**
     * Get the wallet's KeyCrypter, or null if the wallet is not encrypted.
     * (Used in encrypting/ decrypting an ECKey).
     */
    @Nullable
     KeyCrypter getKeyCrypter();

    /**
     * Get the type of encryption used for this wallet.
     *
     * (This is a convenience method - the encryption type is actually stored in the keyCrypter).
     */
     Protos.Wallet.EncryptionType getEncryptionType();

    /** Returns true if the wallet is encrypted using any scheme, false if not. */
     boolean isEncrypted();

    /**
     * Changes wallet encryption password, this is atomic operation.
     * @throws Wallet.BadWalletEncryptionKeyException Thrown if the given currentPassword is wrong. If so, the wallet state is unchanged.
     * @throws KeyCrypterException Thrown if the wallet decryption fails. If so, the wallet state is unchanged.
     */
     void changeEncryptionPassword(CharSequence currentPassword, CharSequence newPassword) throws Wallet.BadWalletEncryptionKeyException;

    /**
     * Changes wallet AES encryption key, this is atomic operation.
     * @throws Wallet.BadWalletEncryptionKeyException Thrown if the given currentAesKey is wrong. If so, the wallet state is unchanged.
     * @throws KeyCrypterException Thrown if the wallet decryption fails. If so, the wallet state is unchanged.
     */
     void changeEncryptionKey(KeyCrypter keyCrypter, AesKey currentAesKey, AesKey newAesKey) throws Wallet.BadWalletEncryptionKeyException;
    //endregion

    // ***************************************************************************************************************

    //region Serialization support

    @Deprecated
     List<Protos.Key> serializeKeyChainGroupToProtobuf();

    /** Internal use only. */
    List<Protos.Key> serializeKeyChainGroupToProtobufInternal();

    /**
     * Saves the wallet first to the given temporary file, then renames to the destination file. This is done to make
     * the save an atomic operation.
     *
     * @param tempFile temporary file to use for saving the wallet
     * @param destFile file to save the wallet to
     * @throws FileNotFoundException if directory doesn't exist
     * @throws IOException           if an error occurs while saving
     */
     void saveToFile(File tempFile, File destFile) throws IOException;
    /**
     * Uses protobuf serialization to save the wallet to the given file. To learn more about this file format, see
     * {@link WalletProtobufSerializer}. Writes out first to a temporary file in the same directory and then renames
     * once written.
     * @param f File to save wallet
     * @throws FileNotFoundException if directory doesn't exist
     * @throws IOException if an error occurs while saving
     */
     void saveToFile(File f) throws IOException;

    /**
     * <p>Whether or not the wallet will ignore pending transactions that fail the selected
     * {@link RiskAnalysis}. By default, if a transaction is considered risky then it won't enter the wallet
     * and won't trigger any event listeners. If you set this property to true, then all transactions will
     * be allowed in regardless of risk. For example, the {@link DefaultRiskAnalysis} checks for non-finality of
     * transactions.</p>
     *
     * <p>Note that this property is not serialized. You have to set it each time a Wallet object is constructed,
     * even if it's loaded from a protocol buffer.</p>
     */
     void setAcceptRiskyTransactions(boolean acceptRiskyTransactions);

    /**
     * See {@link Wallet#setAcceptRiskyTransactions(boolean)} for an explanation of this property.
     */
     boolean isAcceptRiskyTransactions();

    /**
     * Sets the {@link RiskAnalysis} implementation to use for deciding whether received pending transactions are risky
     * or not. If the analyzer says a transaction is risky, by default it will be dropped. You can customize this
     * behaviour with {@link #setAcceptRiskyTransactions(boolean)}.
     */
     void setRiskAnalyzer(RiskAnalysis.Analyzer analyzer);

    /**
     * Gets the current {@link RiskAnalysis} implementation. The default is {@link DefaultRiskAnalysis}.
     */
     RiskAnalysis.Analyzer getRiskAnalyzer();

    /**
     * <p>Sets up the wallet to auto-save itself to the given file, using temp files with atomic renames to ensure
     * consistency. After connecting to a file, you no longer need to save the wallet manually, it will do it
     * whenever necessary. Protocol buffer serialization will be used.</p>
     *
     * <p>A background thread will be created and the wallet will only be saved to
     * disk every periodically. If no changes have occurred for the given time period, nothing will be written.
     * In this way disk IO can be rate limited. It's a good idea to set this as otherwise the wallet can change very
     * frequently, e.g. if there are a lot of transactions in it or during block sync, and there will be a lot of redundant
     * writes. Note that when a new key is added, that always results in an immediate save regardless of
     * delay. <b>You should still save the wallet manually using {@link Wallet#saveToFile(File)} when your program
     * is about to shut down as the JVM will not wait for the background thread.</b></p>
     *
     * <p>An event listener can be provided. It will be called on a background thread
     * with the wallet locked when an auto-save occurs.</p>
     *
     * @param f The destination file to save to.
     * @param delay How much time to wait until saving the wallet on a background thread.
     * @param eventListener callback to be informed when the auto-save thread does things, or null
     */
     WalletFiles autosaveToFile(File f, Duration delay, @Nullable WalletFiles.Listener eventListener);

    /**
     * <p>
     * Disables auto-saving, after it had been enabled with
     * {@link Wallet#autosaveToFile(File, Duration, WalletFiles.Listener)}
     * before. This method blocks until finished.
     * </p>
     */
     void shutdownAutosaveAndWait();

    /** Requests an asynchronous save on a background thread */
     void saveLater();

    /** If auto saving is enabled, do an immediate sync write to disk ignoring any delays. */
     void saveNow();

    /**
     * Uses protobuf serialization to save the wallet to the given file stream. To learn more about this file format, see
     * {@link WalletProtobufSerializer}.
     */
     void saveToFileStream(OutputStream f) throws IOException;

    /**
     * Returns if this wallet is structurally consistent, so e.g. no duplicate transactions. First inconsistency and a
     * dump of the wallet will be logged.
     */
     boolean isConsistent();

    /**
     * Variant of {@link Wallet#isConsistent()} that throws an {@link IllegalStateException} describing the first
     * inconsistency.
     */
     void isConsistentOrThrow() throws IllegalStateException;
    /*
     * If isSpent - check that all my outputs spent, otherwise check that there at least
     * one unspent.
     */
    // For testing only
    boolean isTxConsistent(final Transaction tx, final boolean isSpent);


    //endregion

    // ***************************************************************************************************************

    //region Inbound transaction reception and processing


    /**
     * <p>Called when we have found a transaction (via network broadcast or otherwise) that is relevant to this wallet
     * and want to record it. Note that we <b>cannot verify these transactions at all</b>, they may spend fictional
     * coins or be otherwise invalid. They are useful to inform the user about coins they can expect to receive soon,
     * and if you trust the sender of the transaction you can choose to assume they are in fact valid and will not
     * be double spent as an optimization.</p>
     *
     * <p>This is the same as {@link Wallet#receivePending(Transaction, List)} but allows you to override the
     * {@link Wallet#isPendingTransactionRelevant(Transaction)} sanity-check to keep track of transactions that are not
     * spendable or spend our coins. This can be useful when you want to keep track of transaction confidence on
     * arbitrary transactions. Note that transactions added in this way will still be relayed to peers and appear in
     * transaction lists like any other pending transaction (even when not relevant).</p>
     */
     void receivePending(Transaction tx, @Nullable List<Transaction> dependencies, boolean overrideIsRelevant);

    /**
     * Given a transaction and an optional list of dependencies (recursive/flattened), returns true if the given
     * transaction would be rejected by the analyzer, or false otherwise. The result of this call is independent
     * of the value of {@link #isAcceptRiskyTransactions()}. Risky transactions yield a logged warning. If you
     * want to know the reason why a transaction is risky, create an instance of the {@link RiskAnalysis} yourself
     * using the factory returned by {@link #getRiskAnalyzer()} and use it directly.
     */
     boolean isTransactionRisky(Transaction tx, @Nullable List<Transaction> dependencies);

    /**
     * <p>Called when we have found a transaction (via network broadcast or otherwise) that is relevant to this wallet
     * and want to record it. Note that we <b>cannot verify these transactions at all</b>, they may spend fictional
     * coins or be otherwise invalid. They are useful to inform the user about coins they can expect to receive soon,
     * and if you trust the sender of the transaction you can choose to assume they are in fact valid and will not
     * be double spent as an optimization.</p>
     *
     * <p>Before this method is called, {@link Wallet#isPendingTransactionRelevant(Transaction)} should have been
     * called to decide whether the wallet cares about the transaction - if it does, then this method expects the
     * transaction and any dependencies it has which are still in the memory pool.</p>
     */
     void receivePending(Transaction tx, @Nullable List<Transaction> dependencies) throws VerificationException;

    /**
     * This method is used by a {@link Peer} to find out if a transaction that has been announced is interesting,
     * that is, whether we should bother downloading its dependencies and exploring the transaction to decide how
     * risky it is. If this method returns true then {@link Wallet#receivePending(Transaction, List)}
     * will soon be called with the transactions dependencies as well.
     */
     boolean isPendingTransactionRelevant(Transaction tx) throws ScriptException;

    /**
     * <p>Returns true if the given transaction sends coins to any of our keys, or has inputs spending any of our outputs,
     * and also returns true if tx has inputs that are spending outputs which are
     * not ours but which are spent by pending transactions.</p>
     *
     * <p>Note that if the tx has inputs containing one of our keys, but the connected transaction is not in the wallet,
     * it will not be considered relevant.</p>
     */
     boolean isTransactionRelevant(Transaction tx) throws ScriptException;

    /**
     * Determine if a transaction is <i>mature</i>. A coinbase transaction is <i>mature</i> if it has been confirmed at least
     * {@link NetworkParameters#getSpendableCoinbaseDepth()} times. On {@link BitcoinNetwork#MAINNET} this value is {@code 100}.
     * For purposes of this method, non-coinbase transactions are also considered <i>mature</i>.
     * @param tx the transaction to evaluate
     * @return {@code true} if it is a mature coinbase transaction or if it is not a coinbase transaction
     */
     boolean isTransactionMature(Transaction tx);


    /**
     * <p>Called by the {@link BlockChain} when a new block on the best chain is seen, AFTER relevant wallet
     * transactions are extracted and sent to us UNLESS the new block caused a re-org, in which case this will
     * not be called (the {@link Wallet#reorganize(StoredBlock, List, List)} method will
     * call this one in that case).</p>
     * <p>Used to update confidence data in each transaction and last seen block hash. Triggers auto saving.
     * Invokes the onWalletChanged event listener if there were any affected transactions.</p>
     */
    @Override
     void notifyNewBestBlock(StoredBlock block) throws VerificationException;


    /**
     * Updates the wallet with the given transaction: puts it into the pending pool, sets the spent flags and runs
     * the onCoinsSent/onCoinsReceived event listener. Used in two situations:
     * <ol>
     *     <li>When we have just successfully transmitted the tx we created to the network.</li>
     *     <li>When we receive a pending transaction that didn't appear in the chain yet, and we did not create it.</li>
     * </ol>
     * Triggers an auto save (if enabled.)
     * <p>
     * Unlike {@link Wallet#maybeCommitTx} {@code commitTx} throws an exception if the transaction
     * was already added to the wallet.
     *
     * @param tx transaction to commit
     * @throws VerificationException if transaction was already in the pending pool
     */
     void commitTx(Transaction tx) throws VerificationException;

    //endregion

    // ***************************************************************************************************************

    //region Event listeners

    /**
     * Adds an event listener object. Methods on this object are called when something interesting happens,
     * like receiving money. Runs the listener methods in the user thread.
     */
     void addChangeEventListener(WalletChangeEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when something interesting happens,
     * like receiving money. The listener is executed by the given executor.
     */
     void addChangeEventListener(Executor executor, WalletChangeEventListener listener);
    /**
     * Adds an event listener object called when coins are received.
     * Runs the listener methods in the user thread.
     */
     void addCoinsReceivedEventListener(WalletCoinsReceivedEventListener listener);

    /**
     * Adds an event listener object called when coins are received.
     * The listener is executed by the given executor.
     */
     void addCoinsReceivedEventListener(Executor executor, WalletCoinsReceivedEventListener listener);

    /**
     * Adds an event listener object called when coins are sent.
     * Runs the listener methods in the user thread.
     */
     void addCoinsSentEventListener(WalletCoinsSentEventListener listener);

    /**
     * Adds an event listener object called when coins are sent.
     * The listener is executed by the given executor.
     */
     void addCoinsSentEventListener(Executor executor, WalletCoinsSentEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when keys are
     * added. The listener is executed in the user thread.
     */
     void addKeyChainEventListener(KeyChainEventListener listener);
    /**
     * Adds an event listener object. Methods on this object are called when keys are
     * added. The listener is executed by the given executor.
     */
     void addKeyChainEventListener(Executor executor, KeyChainEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when a current key and/or address
     * changes. The listener is executed in the user thread.
     */
     void addCurrentKeyChangeEventListener(CurrentKeyChangeEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when a current key and/or address
     * changes. The listener is executed by the given executor.
     */
     void addCurrentKeyChangeEventListener(Executor executor, CurrentKeyChangeEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when something interesting happens,
     * like receiving money. Runs the listener methods in the user thread.
     */
     void addReorganizeEventListener(WalletReorganizeEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when something interesting happens,
     * like receiving money. The listener is executed by the given executor.
     */
     void addReorganizeEventListener(Executor executor, WalletReorganizeEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when scripts
     * watched by this wallet change. Runs the listener methods in the user thread.
     */
     void addScriptsChangeEventListener(ScriptsChangeEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when scripts
     * watched by this wallet change. The listener is executed by the given executor.
     */
     void addScriptsChangeEventListener(Executor executor, ScriptsChangeEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when confidence
     * of a transaction changes. Runs the listener methods in the user thread.
     */
     void addTransactionConfidenceEventListener(TransactionConfidenceEventListener listener);

    /**
     * Adds an event listener object. Methods on this object are called when confidence
     * of a transaction changes. The listener is executed by the given executor.
     */
     void addTransactionConfidenceEventListener(Executor executor, TransactionConfidenceEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
     boolean removeChangeEventListener(WalletChangeEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
     boolean removeCoinsReceivedEventListener(WalletCoinsReceivedEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
     boolean removeCoinsSentEventListener(WalletCoinsSentEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
     boolean removeKeyChainEventListener(KeyChainEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that
     * listener was never added.
     */
     boolean removeCurrentKeyChangeEventListener(CurrentKeyChangeEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
     boolean removeReorganizeEventListener(WalletReorganizeEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
     boolean removeScriptsChangeEventListener(ScriptsChangeEventListener listener);

    /**
     * Removes the given event listener object. Returns true if the listener was removed, false if that listener
     * was never added.
     */
     boolean removeTransactionConfidenceEventListener(TransactionConfidenceEventListener listener);

    //endregion

    // ***************************************************************************************************************

    //region Vending transactions and other internal state

     boolean checkForFilterExhaustion(FilteredBlock block);

    /**
     * Returns a set of all transactions in the wallet.
     * @param includeDead     If true, transactions that were overridden by a double spend are included.
     */
     Set<Transaction> getTransactions(boolean includeDead);

     void setTransactionBroadcaster(@Nullable org.bitcoinj.core.TransactionBroadcaster broadcaster);

    /**
     * Returns a set of all WalletTransactions in the wallet.
     */
     Iterable<WalletTransaction> getWalletTransactions();

    private static void addWalletTransactionsToSet(Set<WalletTransaction> txns,
                                                   WalletTransaction.Pool poolType, Collection<Transaction> pool) {
        for (Transaction tx : pool) {
            txns.add(new WalletTransaction(poolType, tx));
        }
    }

    /**
     * Adds a transaction that has been associated with a particular wallet pool. This is intended for usage by
     * deserialization code, such as the {@link WalletProtobufSerializer} class. It isn't normally useful for
     * applications. It does not trigger auto saving.
     */
     void addWalletTransaction(WalletTransaction wtx);

    /**
     * Returns all non-dead, active transactions ordered by recency.
     */
     List<Transaction> getTransactionsByTime();

    /**
     * <p>Returns an list of N transactions, ordered by increasing age. Transactions on side chains are not included.
     * Dead transactions (overridden by double spends) are optionally included.</p>
     * <p>Note: the current implementation is O(num transactions in wallet). Regardless of how many transactions are
     * requested, the cost is always the same. In future, requesting smaller numbers of transactions may be faster
     * depending on how the wallet is implemented (e.g. if backed by a database).</p>
     */
     List<Transaction> getRecentTransactions(int numTransactions, boolean includeDead);
    /**
     * Returns a transaction object given its hash, if it exists in this wallet, or null otherwise.
     */
    @Nullable
     Transaction getTransaction(Sha256Hash hash);

    /**
     * Prepares the wallet for a blockchain replay. Removes all transactions (as they would get in the way of the
     * replay) and makes the wallet think it has never seen a block. {@link WalletChangeEventListener#onWalletChanged} will
     * be fired.
     */
     void reset();

    /**
     * Deletes transactions which appeared above the given block height from the wallet, but does not touch the keys.
     * This is useful if you have some keys and wish to replay the block chain into the wallet in order to pick them up.
     * Triggers auto saving.
     */
     void clearTransactions(int fromHeight);


    /**
     * Clean up the wallet. Currently, it only removes risky pending transaction from the wallet and only if their
     * outputs have not been spent.
     */
     void cleanup();

    EnumSet<WalletTransaction.Pool> getContainingPools(Transaction tx);

    @VisibleForTesting
     int getPoolSize(WalletTransaction.Pool pool);

    @VisibleForTesting
     boolean poolContainsTxHash(final WalletTransaction.Pool pool, final Sha256Hash txHash);

    /** Returns a copy of the internal unspent outputs list */
     List<TransactionOutput> getUnspents();

    /**
     * Returns the earliest creation time of keys or watched scripts in this wallet, ie the min
     * of {@link ECKey#getCreationTime()}. This can return {@link Instant#EPOCH} if at least one key does
     * not have that data (e.g. is an imported key with unknown timestamp). <p>
     *
     * This method is most often used in conjunction with {@link PeerGroup#setFastCatchupTime(Instant)} in order to
     * optimize chain download for new users of wallet apps. Backwards compatibility notice: if you get {@link Instant#EPOCH} from this
     * method, you can instead use the time of the first release of your software, as it's guaranteed no users will
     * have wallets pre-dating this time. <p>
     *
     * If there are no keys in the wallet, {@link Instant#MAX} is returned.
     *
     * @return earliest creation times of keys in this wallet,
     *         {@link Instant#EPOCH} if at least one time is unknown,
     *         {@link Instant#MAX} if no keys in this wallet
     */
    @Override
     Instant earliestKeyCreationTime();

    /** Returns the hash of the last seen best-chain block, or null if the wallet is too old to store this data. */
    @Nullable
    Sha256Hash getLastBlockSeenHash();

     void setLastBlockSeenHash(@Nullable Sha256Hash lastBlockSeenHash);

     void setLastBlockSeenHeight(int lastBlockSeenHeight);

     void setLastBlockSeenTime(Instant time);

     void clearLastBlockSeenTime();

    /**
     * Returns time extracted from the last best seen block header, or empty. This timestamp
     * is <b>not</b> the local time at which the block was first observed by this application but rather what the block
     * (i.e. miner) self declares. It is allowed to have some significant drift from the real time at which the block
     * was found, although most miners do use accurate times. If this wallet is old and does not have a recorded
     * time then this method returns zero.
     */
     Optional<Instant> lastBlockSeenTime();

    /**
     * Returns the height of the last seen best-chain block. Can be 0 if a wallet is brand new or -1 if the wallet
     * is old and doesn't have that data.
     */
     int getLastBlockSeenHeight();

    /**
     * Get the version of the Wallet.
     * This is an int you can use to indicate which versions of wallets your code understands,
     * and which come from the future (and hence cannot be safely loaded).
     */
     int getVersion();

    /**
     * Set the version number of the wallet. See {@link Wallet#getVersion()}.
     */
     void setVersion(int version);

    /**
     * Set the description of the wallet.
     * This is a Unicode encoding string typically entered by the user as descriptive text for the wallet.
     */
     void setDescription(String description);

    /**
     * Get the description of the wallet. See {@link Wallet#setDescription(String)}
     */
     String getDescription();

    //endregion

    // ***************************************************************************************************************

    //region Balance and balance futures

    /**
     * <p>It's possible to calculate a wallets balance from multiple points of view. This enum selects which
     * {@link #getBalance(Wallet.BalanceType)} should use.</p>
     *
     * <p>Consider a real-world example: you buy a snack costing $5 but you only have a $10 bill. At the start you have
     * $10 viewed from every possible angle. After you order the snack you hand over your $10 bill. From the
     * perspective of your wallet you have zero dollars (AVAILABLE). But you know in a few seconds the shopkeeper
     * will give you back $5 change so most people in practice would say they have $5 (ESTIMATED).</p>
     *
     * <p>The fact that the wallet can track transactions which are not spendable by itself ("watching wallets") adds
     * another type of balance to the mix. Although the wallet won't do this by default, advanced use cases that
     * override the relevancy checks can end up with a mix of spendable and unspendable transactions.</p>
     */
     enum BalanceType {
        /**
         * Balance calculated assuming all pending transactions are in fact included into the best chain by miners.
         * This includes the value of immature coinbase transactions.
         */
        ESTIMATED,

        /**
         * Balance that could be safely used to create new spends, if we had all the needed private keys. This is
         * whatever the default coin selector would make available, which by default means transaction outputs with at
         * least 1 confirmation and pending transactions created by our own wallet which have been propagated across
         * the network. Whether we <i>actually</i> have the private keys or not is irrelevant for this balance type.
         */
        AVAILABLE,

        /** Same as ESTIMATED but only for outputs we have the private keys for and can sign ourselves. */
        ESTIMATED_SPENDABLE,
        /** Same as AVAILABLE but only for outputs we have the private keys for and can sign ourselves. */
        AVAILABLE_SPENDABLE
    }

    /**
     * Returns the AVAILABLE balance of this wallet. See {@link Wallet.BalanceType#AVAILABLE} for details on what this
     * means.
     */
     Coin getBalance();

    /**
     * Returns the balance of this wallet as calculated by the provided balanceType.
     */
     Coin getBalance(Wallet.BalanceType balanceType);

    /**
     * Returns the balance that would be considered spendable by the given coin selector, including watched outputs
     * (i.e. balance includes outputs we don't have the private keys for). Just asks it to select as many coins as
     * possible and returns the total.
     */
     Coin getBalance(CoinSelector selector);

    /**
     * Returns the amount of bitcoin ever received via output. <b>This is not the balance!</b> If an output spends from a
     * transaction whose inputs are also to our wallet, the input amounts are deducted from the outputs contribution, with a minimum of zero
     * contribution. The idea behind this is we avoid double counting money sent to us.
     * @return the total amount of satoshis received, regardless of whether it was spent or not.
     */
     Coin getTotalReceived();

    /**
     * Returns the amount of bitcoin ever sent via output. If an output is sent to our own wallet, because of change or
     * rotating keys or whatever, we do not count it. If the wallet was
     * involved in a shared transaction, i.e. there is some input to the transaction that we don't have the key for, then
     * we multiply the sum of the output values by the proportion of satoshi coming in to our inputs. Essentially we treat
     * inputs as pooling into the transaction, becoming fungible and being equally distributed to all outputs.
     * @return the total amount of satoshis sent by us
     */
    Coin getTotalSent();

    //endregion

    // ***************************************************************************************************************

    //region Creating and sending transactions


    /**
     * Enumerates possible resolutions for missing signatures.
     */
     enum MissingSigsMode {
        /** Input script will have OP_0 instead of missing signatures */
        USE_OP_ZERO,
        /**
         * Missing signatures will be replaced by dummy sigs. This is useful when you'd like to know the fee for
         * a transaction without knowing the user's password, as fee depends on size.
         */
        USE_DUMMY_SIG,
        /**
         * If signature is missing, {@link TransactionSigner.MissingSignatureException}
         * will be thrown for P2SH and {@link ECKey.MissingPrivateKeyException} for other tx types.
         */
        THROW
    }

    /**
     * <p>Statelessly creates a transaction that sends the given value to address. The change is sent to
     * {@link Wallet#currentChangeAddress()}, so you must have added at least one key.</p>
     *
     * <p>If you just want to send money quickly, you probably want
     * {@link Wallet#sendCoins(TransactionBroadcaster, Address, Coin)} instead. That will create the sending
     * transaction, commit to the wallet and broadcast it to the network all in one go. This method is lower level
     * and lets you see the proposed transaction before anything is done with it.</p>
     *
     * <p>This is a helper method that is equivalent to using {@link SendRequest#to(Address, Coin)}
     * followed by {@link Wallet#completeTx(SendRequest)} and returning the requests transaction object.
     * Note that this means a fee may be automatically added if required, if you want more control over the process,
     * just do those two steps yourself.</p>
     *
     * <p>IMPORTANT: This method does NOT update the wallet. If you call createSend again you may get two transactions
     * that spend the same coins. You have to call {@link Wallet#commitTx(Transaction)} on the created transaction to
     * prevent this, but that should only occur once the transaction has been accepted by the network. This implies
     * you cannot have more than one outstanding sending tx at once.</p>
     *
     * <p>You MUST ensure that the value is not smaller than {@link TransactionOutput#getMinNonDustValue()} or the transaction
     * will almost certainly be rejected by the network as dust.</p>
     *
     * @param address The Bitcoin address to send the money to.
     * @param value How much currency to send.
     * @return either the created Transaction or null if there are insufficient coins.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws Wallet.DustySendRequested if the resultant transaction would violate the dust rules.
     * @throws Wallet.CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws Wallet.ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process.
     * @throws Wallet.MultipleOpReturnRequested if there is more than one OP_RETURN output for the resultant transaction.
     * @throws Wallet.BadWalletEncryptionKeyException if the supplied {@link SendRequest#aesKey} is wrong.
     */
     Transaction createSend(Address address, Coin value)
            throws InsufficientMoneyException, Wallet.CompletionException;

    /**
     * <p>Statelessly creates a transaction that sends the given value to address. The change is sent to
     * {@link Wallet#currentChangeAddress()}, so you must have added at least one key.</p>
     *
     * <p>If you just want to send money quickly, you probably want
     * {@link Wallet#sendCoins(TransactionBroadcaster, Address, Coin)} instead. That will create the sending
     * transaction, commit to the wallet and broadcast it to the network all in one go. This method is lower level
     * and lets you see the proposed transaction before anything is done with it.</p>
     *
     * <p>This is a helper method that is equivalent to using {@link SendRequest#to(Address, Coin)}
     * followed by {@link Wallet#completeTx(SendRequest)} and returning the requests transaction object.
     * Note that this means a fee may be automatically added if required, if you want more control over the process,
     * just do those two steps yourself.</p>
     *
     * <p>IMPORTANT: This method does NOT update the wallet. If you call createSend again you may get two transactions
     * that spend the same coins. You have to call {@link Wallet#commitTx(Transaction)} on the created transaction to
     * prevent this, but that should only occur once the transaction has been accepted by the network. This implies
     * you cannot have more than one outstanding sending tx at once.</p>
     *
     * <p>You MUST ensure that the value is not smaller than {@link TransactionOutput#getMinNonDustValue()} or the transaction
     * will almost certainly be rejected by the network as dust.</p>
     *
     * @param address The Bitcoin address to send the money to.
     * @param value How much currency to send.
     * @param allowUnconfirmed Whether to allow spending unconfirmed outputs.
     * @return either the created Transaction or null if there are insufficient coins.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws Wallet.DustySendRequested if the resultant transaction would violate the dust rules.
     * @throws Wallet.CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws Wallet.ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process.
     * @throws Wallet.MultipleOpReturnRequested if there is more than one OP_RETURN output for the resultant transaction.
     * @throws Wallet.BadWalletEncryptionKeyException if the supplied {@link SendRequest#aesKey} is wrong.
     */
     Transaction createSend(Address address, Coin value, boolean allowUnconfirmed)
            throws InsufficientMoneyException, Wallet.CompletionException;

    /**
     * Sends coins to the given address but does not broadcast the resulting pending transaction. It is still stored
     * in the wallet, so when the wallet is added to a {@link PeerGroup} or {@link Peer} the transaction will be
     * announced to the network. The given {@link SendRequest} is completed first using
     * {@link Wallet#completeTx(SendRequest)} to make it valid.
     *
     * @return the Transaction that was created
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice
     * @throws Wallet.DustySendRequested if the resultant transaction would violate the dust rules.
     * @throws Wallet.CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws Wallet.ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process.
     * @throws Wallet.MultipleOpReturnRequested if there is more than one OP_RETURN output for the resultant transaction.
     * @throws Wallet.BadWalletEncryptionKeyException if the supplied {@link SendRequest#aesKey} is wrong.
     */
     Transaction sendCoinsOffline(SendRequest request)
            throws InsufficientMoneyException, Wallet.CompletionException;

    /**
     * <p>Sends coins to the given address, via the given {@link PeerGroup}. Change is returned to
     * {@link Wallet#currentChangeAddress()}. Note that a fee may be automatically added if one may be required for the
     * transaction to be confirmed.</p>
     *
     * <p>The returned object provides both the transaction, and a future that can be used to learn when the broadcast
     * is complete. Complete means, if the PeerGroup is limited to only one connection, when it was written out to
     * the socket. Otherwise when the transaction is written out and we heard it back from a different peer.</p>
     *
     * <p>Note that the sending transaction is committed to the wallet immediately, not when the transaction is
     * successfully broadcast. This means that even if the network hasn't heard about your transaction you won't be
     * able to spend those same coins again.</p>
     *
     * <p>You MUST ensure that value is not smaller than {@link TransactionOutput#getMinNonDustValue()} or the transaction will
     * almost certainly be rejected by the network as dust.</p>
     *
     * @param broadcaster a {@link TransactionBroadcaster} to use to send the transactions out.
     * @param to Which address to send coins to.
     * @param value How much value to send.
     * @return An object containing the transaction that was created, and a future for the broadcast of it.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws Wallet.DustySendRequested if the resultant transaction would violate the dust rules.
     * @throws Wallet.CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws Wallet.ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process.
     * @throws Wallet.MultipleOpReturnRequested if there is more than one OP_RETURN output for the resultant transaction.
     * @throws Wallet.BadWalletEncryptionKeyException if the supplied {@link SendRequest#aesKey} is wrong.
     */
     Wallet.SendResult sendCoins(TransactionBroadcaster broadcaster, Address to, Coin value)
            throws InsufficientMoneyException, Wallet.CompletionException;

    /**
     * Sends coins to the given address, via the given {@link Peer}. Change is returned to {@link Wallet#currentChangeAddress()}.
     * If an exception is thrown by {@link Peer#sendMessage(Message)} the transaction is still committed, so the
     * pending transaction must be broadcast <b>by you</b> at some other time. Note that a fee may be automatically added
     * if one may be required for the transaction to be confirmed.
     *
     * @return The {@link Transaction} that was created or null if there was insufficient balance to send the coins.
     * @throws InsufficientMoneyException if the request could not be completed due to not enough balance.
     * @throws IllegalArgumentException if you try and complete the same SendRequest twice
     * @throws Wallet.DustySendRequested if the resultant transaction would violate the dust rules.
     * @throws Wallet.CouldNotAdjustDownwards if emptying the wallet was requested and the output can't be shrunk for fees without violating a protocol rule.
     * @throws Wallet.ExceededMaxTransactionSize if the resultant transaction is too big for Bitcoin to process.
     * @throws Wallet.MultipleOpReturnRequested if there is more than one OP_RETURN output for the resultant transaction.
     * @throws Wallet.BadWalletEncryptionKeyException if the supplied {@link SendRequest#aesKey} is wrong.
     */
     Transaction sendCoins(Peer peer, SendRequest request)
            throws InsufficientMoneyException, Wallet.CompletionException;
    
    /**
     * Initiate sending the transaction in a {@link SendRequest}. Calls {@link Wallet#sendCoins(SendRequest)} which
     * performs the following significant operations internally:
     * <ol>
     *     <li>{@link Wallet#completeTx(SendRequest)} -- calculate change and sign</li>
     *     <li>{@link Wallet#commitTx(Transaction)} -- puts the transaction in the {@code Wallet}'s pending pool</li>
     *     <li>{@link org.bitcoinj.core.TransactionBroadcaster#broadcastTransaction(Transaction)} typically implemented by {@link org.bitcoinj.core.PeerGroup#broadcastTransaction(Transaction)} -- queues requests to send the transaction to a single remote {@code Peer}</li>
     * </ol>
     * This method will <i>complete</i> and return a {@link TransactionBroadcast} when the send to the remote peer occurs (is buffered.)
     * The broadcast process includes the following steps:
     * <ol>
     *     <li>Wait until enough {@link org.bitcoinj.core.Peer}s are connected.</li>
     *     <li>Broadcast (buffer for send) the transaction to a single remote {@link org.bitcoinj.core.Peer}</li>
     *     <li>Mark {@link TransactionBroadcast#awaitSent()} as complete</li>
     *     <li>Wait for a number of remote peers to confirm they have received the broadcast</li>
     *     <li>Mark {@link TransactionBroadcast#awaitRelayed()} as complete</li>
     * </ol>
     * @param sendRequest transaction to send
     * @return A future for the transaction broadcast
     */
     CompletableFuture<TransactionBroadcast> sendTransaction(SendRequest sendRequest);

    /**
     * Wait for at least 1 confirmation on a transaction.
     * @param tx the transaction we are waiting for
     * @return a future for an object that contains transaction confidence information
     */
     CompletableFuture<TransactionConfidence> waitForConfirmation(Transaction tx);

    /**
     * Wait for a required number of confirmations on a transaction.
     * @param tx the transaction we are waiting for
     * @param requiredConfirmations the minimum required confirmations before completing
     * @return a future for an object that contains transaction confidence information
     */
     CompletableFuture<TransactionConfidence> waitForConfirmations(Transaction tx, int requiredConfirmations);

    TransactionConfidence getConfidence(Transaction tx);


    /**
     * Connect unconnected inputs with outputs from the wallet
     * @param candidates A list of spend candidates from a Wallet
     * @param inputs a list of possibly unconnected/unvalued inputs (e.g. from a spend request)
     * @return a list of the same inputs, but connected/valued if not previously valued and found in wallet
     */
    // For testing only
    static List<TransactionInput> connectInputs(List<TransactionOutput> candidates, List<TransactionInput> inputs) {
        return inputs.stream()
                .map(in -> candidates.stream()
                        .filter(utxo -> utxo.getOutPointFor().equals(in.getOutpoint()))
                        .findFirst()
                        .map(o -> new TransactionInput(o.getParentTransaction(), o.getScriptPubKey().program(), o.getOutPointFor(), o.getValue()))
                        .orElse(in))
                .collect(StreamUtils.toUnmodifiableList());
    }

    /**
     * Is a UTXO already included (to be spent) in a list of transaction inputs?
     * @param inputs the list of inputs to check
     * @param output the transaction output
     * @return true if it is already included, false otherwise
     */
    private boolean alreadyIncluded(List<TransactionInput> inputs, TransactionOutput output) {
        return inputs.stream().noneMatch(i -> i.getOutpoint().equals(output.getOutPointFor()));
    }

     static class FeeCalculation {
        // Selected UTXOs to spend
         CoinSelection bestCoinSelection;
        // Change output (may be null if no change)
         TransactionOutput bestChangeOutput;
        // List of output values adjusted downwards when recipients pay fees (may be null if no adjustment needed).
         List<Coin> updatedOutputValues;
    }

    //region Fee calculation code

     FeeCalculation calculateFee(SendRequest req, Coin value, boolean needAtLeastReferenceFee, List<TransactionOutput> candidates) throws InsufficientMoneyException;


    //endregion

}
