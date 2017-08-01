/*
 * Copyright 2012 Google Inc.
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.*;
import org.bitcoinj.core.TransactionConfidence.ConfidenceType;
import org.bitcoinj.crypto.KeyCrypter;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.utils.ExchangeRate;
import org.bitcoinj.utils.Fiat;
import org.bitcoinj.wallet.Protos.Wallet.EncryptionType;

import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.TextFormat;
import com.google.protobuf.WireFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Serialize and de-serialize a wallet to a byte stream containing a
 * <a href="https://developers.google.com/protocol-buffers/docs/overview">protocol buffer</a>. Protocol buffers are
 * a data interchange format developed by Google with an efficient binary representation, a type safe specification
 * language and compilers that generate code to work with those data structures for many languages. Protocol buffers
 * can have their format evolved over time: conceptually they represent data using (tag, length, value) tuples. The
 * format is defined by the <tt>wallet.proto</tt> file in the bitcoinj source distribution.<p>
 *
 * This class is used through its static methods. The most common operations are writeWallet and readWallet, which do
 * the obvious operations on Output/InputStreams. You can use a {@link java.io.ByteArrayInputStream} and equivalent
 * {@link java.io.ByteArrayOutputStream} if you'd like byte arrays instead. The protocol buffer can also be manipulated
 * in its object form if you'd like to modify the flattened data structure before serialization to binary.<p>
 *
 * You can extend the wallet format with additional fields specific to your application if you want, but make sure
 * to either put the extra data in the provided extension areas, or select tag numbers that are unlikely to be used
 * by anyone else.<p>
 *
 * @author Miron Cuperman
 * @author Andreas Schildbach
 */
public class WalletProtobufSerializer {
    private static final Logger log = LoggerFactory.getLogger(WalletProtobufSerializer.class);
    /** Current version used for serializing wallets. A version higher than this is considered from the future. */
    public static final int CURRENT_WALLET_VERSION = Protos.Wallet.getDefaultInstance().getVersion();
    // 512 MB
    private static final int WALLET_SIZE_LIMIT = 512 * 1024 * 1024;
    // Used for de-serialization
    protected Map<ByteString, Transaction> txMap;

    private boolean requireMandatoryExtensions = true;
    private boolean requireAllExtensionsKnown = false;
    private int walletWriteBufferSize = CodedOutputStream.DEFAULT_BUFFER_SIZE;

    public interface WalletFactory {
        Wallet create(NetworkParameters params, KeyChainGroup keyChainGroup);
    }

    private final WalletFactory factory;
    private KeyChainFactory keyChainFactory;

    public WalletProtobufSerializer() {
        this(new WalletFactory() {
            @Override
            public Wallet create(NetworkParameters params, KeyChainGroup keyChainGroup) {
                return new Wallet(params, keyChainGroup);
            }
        });
    }

    public WalletProtobufSerializer(WalletFactory factory) {
        txMap = new HashMap<>();
        this.factory = factory;
        this.keyChainFactory = new DefaultKeyChainFactory();
    }

    public void setKeyChainFactory(KeyChainFactory keyChainFactory) {
        this.keyChainFactory = keyChainFactory;
    }

    /**
     * If this property is set to false, then unknown mandatory extensions will be ignored instead of causing load
     * errors. You should only use this if you know exactly what you are doing, as the extension data will NOT be
     * round-tripped, possibly resulting in a corrupted wallet if you save it back out again.
     */
    public void setRequireMandatoryExtensions(boolean value) {
        requireMandatoryExtensions = value;
    }

    /**
     * If this property is set to true, the wallet will fail to load if  any found extensions are unknown..
     */
    public void setRequireAllExtensionsKnown(boolean value) {
        requireAllExtensionsKnown = value;
    }

    /**
     * Change buffer size for writing wallet to output stream. Default is {@link com.google.protobuf.CodedOutputStream#DEFAULT_BUFFER_SIZE}
     * @param walletWriteBufferSize - buffer size in bytes
     */
    public void setWalletWriteBufferSize(int walletWriteBufferSize) {
        this.walletWriteBufferSize = walletWriteBufferSize;
    }

    /**
     * Formats the given wallet (transactions and keys) to the given output stream in protocol buffer format.<p>
     *
     * Equivalent to <tt>walletToProto(wallet).writeTo(output);</tt>
     */
    public void writeWallet(Wallet wallet, OutputStream output) throws IOException {
        Protos.Wallet walletProto = walletToProto(wallet);
        final CodedOutputStream codedOutput = CodedOutputStream.newInstance(output, this.walletWriteBufferSize);
        walletProto.writeTo(codedOutput);
        codedOutput.flush();
    }

    /**
     * Returns the given wallet formatted as text. The text format is that used by protocol buffers and although it
     * can also be parsed using {@link TextFormat#merge(CharSequence, com.google.protobuf.Message.Builder)},
     * it is designed more for debugging than storage. It is not well specified and wallets are largely binary data
     * structures anyway, consisting as they do of keys (large random numbers) and {@link Transaction}s which also
     * mostly contain keys and hashes.
     */
    public String walletToText(Wallet wallet) {
        Protos.Wallet walletProto = walletToProto(wallet);
        return TextFormat.printToString(walletProto);
    }

    /**
     * Converts the given wallet to the object representation of the protocol buffers. This can be modified, or
     * additional data fields set, before serialization takes place.
     */
    public Protos.Wallet walletToProto(Wallet wallet) {
        Protos.Wallet.Builder walletBuilder = Protos.Wallet.newBuilder();
        walletBuilder.setNetworkIdentifier(wallet.getNetworkParameters().getId());
        if (wallet.getDescription() != null) {
            walletBuilder.setDescription(wallet.getDescription());
        }

        for (WalletTransaction wtx : wallet.getWalletTransactions()) {
            Protos.Transaction txProto = makeTxProto(wtx);
            walletBuilder.addTransaction(txProto);
        }

        walletBuilder.addAllKey(wallet.serializeKeyChainGroupToProtobuf());

        for (Script script : wallet.getWatchedScripts()) {
            Protos.Script protoScript =
                    Protos.Script.newBuilder()
                            .setProgram(ByteString.copyFrom(script.getProgram()))
                            .setCreationTimestamp(script.getCreationTimeSeconds() * 1000)
                            .build();

            walletBuilder.addWatchedScript(protoScript);
        }

        // Populate the lastSeenBlockHash field.
        Sha256Hash lastSeenBlockHash = wallet.getLastBlockSeenHash();
        if (lastSeenBlockHash != null) {
            walletBuilder.setLastSeenBlockHash(hashToByteString(lastSeenBlockHash));
            walletBuilder.setLastSeenBlockHeight(wallet.getLastBlockSeenHeight());
        }
        if (wallet.getLastBlockSeenTimeSecs() > 0)
            walletBuilder.setLastSeenBlockTimeSecs(wallet.getLastBlockSeenTimeSecs());

        // Populate the scrypt parameters.
        KeyCrypter keyCrypter = wallet.getKeyCrypter();
        if (keyCrypter == null) {
            // The wallet is unencrypted.
            walletBuilder.setEncryptionType(EncryptionType.UNENCRYPTED);
        } else {
            // The wallet is encrypted.
            walletBuilder.setEncryptionType(keyCrypter.getUnderstoodEncryptionType());
            if (keyCrypter instanceof KeyCrypterScrypt) {
                KeyCrypterScrypt keyCrypterScrypt = (KeyCrypterScrypt) keyCrypter;
                walletBuilder.setEncryptionParameters(keyCrypterScrypt.getScryptParameters());
            } else {
                // Some other form of encryption has been specified that we do not know how to persist.
                throw new RuntimeException("The wallet has encryption of type '" + keyCrypter.getUnderstoodEncryptionType() + "' but this WalletProtobufSerializer does not know how to persist this.");
            }
        }

        if (wallet.getKeyRotationTime() != null) {
            long timeSecs = wallet.getKeyRotationTime().getTime() / 1000;
            walletBuilder.setKeyRotationTime(timeSecs);
        }

        populateExtensions(wallet, walletBuilder);

        for (Map.Entry<String, ByteString> entry : wallet.getTags().entrySet()) {
            Protos.Tag.Builder tag = Protos.Tag.newBuilder().setTag(entry.getKey()).setData(entry.getValue());
            walletBuilder.addTags(tag);
        }

        for (TransactionSigner signer : wallet.getTransactionSigners()) {
            // do not serialize LocalTransactionSigner as it's being added implicitly
            if (signer instanceof LocalTransactionSigner)
                continue;
            Protos.TransactionSigner.Builder protoSigner = Protos.TransactionSigner.newBuilder();
            protoSigner.setClassName(signer.getClass().getName());
            protoSigner.setData(ByteString.copyFrom(signer.serialize()));
            walletBuilder.addTransactionSigners(protoSigner);
        }

        // Populate the wallet version.
        walletBuilder.setVersion(wallet.getVersion());

        return walletBuilder.build();
    }

    private static void populateExtensions(Wallet wallet, Protos.Wallet.Builder walletBuilder) {
        for (WalletExtension extension : wallet.getExtensions().values()) {
            Protos.Extension.Builder proto = Protos.Extension.newBuilder();
            proto.setId(extension.getWalletExtensionID());
            proto.setMandatory(extension.isWalletExtensionMandatory());
            proto.setData(ByteString.copyFrom(extension.serializeWalletExtension()));
            walletBuilder.addExtension(proto);
        }
    }

    private static Protos.Transaction makeTxProto(WalletTransaction wtx) {
        Transaction tx = wtx.getTransaction();
        Protos.Transaction.Builder txBuilder = Protos.Transaction.newBuilder();

        txBuilder.setPool(getProtoPool(wtx))
                 .setHash(hashToByteString(tx.getHash()))
                 .setVersion((int) tx.getVersion());

        if (tx.getUpdateTime() != null) {
            txBuilder.setUpdatedAt(tx.getUpdateTime().getTime());
        }

        if (tx.getLockTime() > 0) {
            txBuilder.setLockTime((int)tx.getLockTime());
        }

        // Handle inputs.
        for (int i = 0; i < tx.getInputs().size(); i++) {
            TransactionInput input = tx.getInput(i);
            Protos.TransactionInput.Builder inputBuilder = Protos.TransactionInput.newBuilder()
                .setScriptBytes(ByteString.copyFrom(input.getScriptBytes()))
                .setTransactionOutPointHash(hashToByteString(input.getOutpoint().getHash()))
                .setTransactionOutPointIndex((int) input.getOutpoint().getIndex());
            if (input.hasSequence())
                inputBuilder.setSequence((int) input.getSequenceNumber());
            if (input.getValue() != null)
                inputBuilder.setValue(input.getValue().value);
            if (tx.hasWitness() && tx.getWitness(i).getPushCount() > 0) {
                TransactionWitness witness = tx.getWitness(i);
                Protos.ScriptWitness.Builder witnessBuilder = Protos.ScriptWitness.newBuilder();
                for(int j = 0; j < witness.getPushCount(); j++) {
                    witnessBuilder.addData(ByteString.copyFrom(witness.getPush(j)));
                }
                inputBuilder.setWitness(witnessBuilder);
            }
            txBuilder.addTransactionInput(inputBuilder);
        }

        // Handle outputs.
        for (TransactionOutput output : tx.getOutputs()) {
            Protos.TransactionOutput.Builder outputBuilder = Protos.TransactionOutput.newBuilder()
                .setScriptBytes(ByteString.copyFrom(output.getScriptBytes()))
                .setValue(output.getValue().value);
            final TransactionInput spentBy = output.getSpentBy();
            if (spentBy != null) {
                Sha256Hash spendingHash = spentBy.getParentTransaction().getHash();
                int spentByTransactionIndex = spentBy.getParentTransaction().getInputs().indexOf(spentBy);
                outputBuilder.setSpentByTransactionHash(hashToByteString(spendingHash))
                             .setSpentByTransactionIndex(spentByTransactionIndex);
            }
            txBuilder.addTransactionOutput(outputBuilder);
        }

        // Handle which blocks tx was seen in.
        final Map<Sha256Hash, Integer> appearsInHashes = tx.getAppearsInHashes();
        if (appearsInHashes != null) {
            for (Map.Entry<Sha256Hash, Integer> entry : appearsInHashes.entrySet()) {
                txBuilder.addBlockHash(hashToByteString(entry.getKey()));
                txBuilder.addBlockRelativityOffsets(entry.getValue());
            }
        }

        if (tx.hasConfidence()) {
            TransactionConfidence confidence = tx.getConfidence();
            Protos.TransactionConfidence.Builder confidenceBuilder = Protos.TransactionConfidence.newBuilder();
            writeConfidence(txBuilder, confidence, confidenceBuilder);
        }

        Protos.Transaction.Purpose purpose;
        switch (tx.getPurpose()) {
            case UNKNOWN: purpose = Protos.Transaction.Purpose.UNKNOWN; break;
            case USER_PAYMENT: purpose = Protos.Transaction.Purpose.USER_PAYMENT; break;
            case KEY_ROTATION: purpose = Protos.Transaction.Purpose.KEY_ROTATION; break;
            case ASSURANCE_CONTRACT_CLAIM: purpose = Protos.Transaction.Purpose.ASSURANCE_CONTRACT_CLAIM; break;
            case ASSURANCE_CONTRACT_PLEDGE: purpose = Protos.Transaction.Purpose.ASSURANCE_CONTRACT_PLEDGE; break;
            case ASSURANCE_CONTRACT_STUB: purpose = Protos.Transaction.Purpose.ASSURANCE_CONTRACT_STUB; break;
            case RAISE_FEE: purpose = Protos.Transaction.Purpose.RAISE_FEE; break;
            default:
                throw new RuntimeException("New tx purpose serialization not implemented.");
        }
        txBuilder.setPurpose(purpose);

        ExchangeRate exchangeRate = tx.getExchangeRate();
        if (exchangeRate != null) {
            Protos.ExchangeRate.Builder exchangeRateBuilder = Protos.ExchangeRate.newBuilder()
                    .setCoinValue(exchangeRate.coin.value).setFiatValue(exchangeRate.fiat.value)
                    .setFiatCurrencyCode(exchangeRate.fiat.currencyCode);
            txBuilder.setExchangeRate(exchangeRateBuilder);
        }

        if (tx.getMemo() != null)
            txBuilder.setMemo(tx.getMemo());

        return txBuilder.build();
    }

    private static Protos.Transaction.Pool getProtoPool(WalletTransaction wtx) {
        switch (wtx.getPool()) {
            case UNSPENT: return Protos.Transaction.Pool.UNSPENT;
            case SPENT: return Protos.Transaction.Pool.SPENT;
            case DEAD: return Protos.Transaction.Pool.DEAD;
            case PENDING: return Protos.Transaction.Pool.PENDING;
            default:
                throw new RuntimeException("Unreachable");
        }
    }

    private static void writeConfidence(Protos.Transaction.Builder txBuilder,
                                        TransactionConfidence confidence,
                                        Protos.TransactionConfidence.Builder confidenceBuilder) {
        synchronized (confidence) {
            confidenceBuilder.setType(Protos.TransactionConfidence.Type.valueOf(confidence.getConfidenceType().getValue()));
            if (confidence.getConfidenceType() == ConfidenceType.BUILDING) {
                confidenceBuilder.setAppearedAtHeight(confidence.getAppearedAtChainHeight());
                confidenceBuilder.setDepth(confidence.getDepthInBlocks());
            }
            if (confidence.getConfidenceType() == ConfidenceType.DEAD) {
                // Copy in the overriding transaction, if available.
                // (A dead coinbase transaction has no overriding transaction).
                if (confidence.getOverridingTransaction() != null) {
                    Sha256Hash overridingHash = confidence.getOverridingTransaction().getHash();
                    confidenceBuilder.setOverridingTransaction(hashToByteString(overridingHash));
                }
            }
            TransactionConfidence.Source source = confidence.getSource();
            switch (source) {
                case SELF: confidenceBuilder.setSource(Protos.TransactionConfidence.Source.SOURCE_SELF); break;
                case NETWORK: confidenceBuilder.setSource(Protos.TransactionConfidence.Source.SOURCE_NETWORK); break;
                case UNKNOWN:
                    // Fall through.
                default:
                    confidenceBuilder.setSource(Protos.TransactionConfidence.Source.SOURCE_UNKNOWN); break;
            }
        }

        for (PeerAddress address : confidence.getBroadcastBy()) {
            Protos.PeerAddress proto = Protos.PeerAddress.newBuilder()
                    .setIpAddress(ByteString.copyFrom(address.getAddr().getAddress()))
                    .setPort(address.getPort())
                    .setServices(address.getServices().longValue())
                    .build();
            confidenceBuilder.addBroadcastBy(proto);
        }
        Date lastBroadcastedAt = confidence.getLastBroadcastedAt();
        if (lastBroadcastedAt != null)
            confidenceBuilder.setLastBroadcastedAt(lastBroadcastedAt.getTime());
        txBuilder.setConfidence(confidenceBuilder);
    }

    public static ByteString hashToByteString(Sha256Hash hash) {
        return ByteString.copyFrom(hash.getBytes());
    }

    public static Sha256Hash byteStringToHash(ByteString bs) {
        return Sha256Hash.wrap(bs.toByteArray());
    }

    /**
     * <p>Loads wallet data from the given protocol buffer and inserts it into the given Wallet object. This is primarily
     * useful when you wish to pre-register extension objects. Note that if loading fails the provided Wallet object
     * may be in an indeterminate state and should be thrown away.</p>
     *
     * <p>A wallet can be unreadable for various reasons, such as inability to open the file, corrupt data, internally
     * inconsistent data, a wallet extension marked as mandatory that cannot be handled and so on. You should always
     * handle {@link UnreadableWalletException} and communicate failure to the user in an appropriate manner.</p>
     *
     * @throws UnreadableWalletException thrown in various error conditions (see description).
     */
    public Wallet readWallet(InputStream input, @Nullable WalletExtension... walletExtensions) throws UnreadableWalletException {
        return readWallet(input, false, walletExtensions);
    }

    /**
     * <p>Loads wallet data from the given protocol buffer and inserts it into the given Wallet object. This is primarily
     * useful when you wish to pre-register extension objects. Note that if loading fails the provided Wallet object
     * may be in an indeterminate state and should be thrown away. Do not simply call this method again on the same
     * Wallet object with {@code forceReset} set {@code true}. It won't work.</p>
     *
     * <p>If {@code forceReset} is {@code true}, then no transactions are loaded from the wallet, and it is configured
     * to replay transactions from the blockchain (as if the wallet had been loaded and {@link Wallet#reset()}
     * had been called immediately thereafter).
     *
     * <p>A wallet can be unreadable for various reasons, such as inability to open the file, corrupt data, internally
     * inconsistent data, a wallet extension marked as mandatory that cannot be handled and so on. You should always
     * handle {@link UnreadableWalletException} and communicate failure to the user in an appropriate manner.</p>
     *
     * @throws UnreadableWalletException thrown in various error conditions (see description).
     */
    public Wallet readWallet(InputStream input, boolean forceReset, @Nullable WalletExtension[] extensions) throws UnreadableWalletException {
        try {
            Protos.Wallet walletProto = parseToProto(input);
            final String paramsID = walletProto.getNetworkIdentifier();
            NetworkParameters params = NetworkParameters.fromID(paramsID);
            if (params == null)
                throw new UnreadableWalletException("Unknown network parameters ID " + paramsID);
            return readWallet(params, extensions, walletProto, forceReset);
        } catch (IOException e) {
            throw new UnreadableWalletException("Could not parse input stream to protobuf", e);
        } catch (IllegalStateException e) {
            throw new UnreadableWalletException("Could not parse input stream to protobuf", e);
        } catch (IllegalArgumentException e) {
            throw new UnreadableWalletException("Could not parse input stream to protobuf", e);
        }
    }

    /**
     * <p>Loads wallet data from the given protocol buffer and inserts it into the given Wallet object. This is primarily
     * useful when you wish to pre-register extension objects. Note that if loading fails the provided Wallet object
     * may be in an indeterminate state and should be thrown away.</p>
     *
     * <p>A wallet can be unreadable for various reasons, such as inability to open the file, corrupt data, internally
     * inconsistent data, a wallet extension marked as mandatory that cannot be handled and so on. You should always
     * handle {@link UnreadableWalletException} and communicate failure to the user in an appropriate manner.</p>
     *
     * @throws UnreadableWalletException thrown in various error conditions (see description).
     */
    public Wallet readWallet(NetworkParameters params, @Nullable WalletExtension[] extensions,
                             Protos.Wallet walletProto) throws UnreadableWalletException {
        return readWallet(params, extensions, walletProto, false);
    }

    /**
     * <p>Loads wallet data from the given protocol buffer and inserts it into the given Wallet object. This is primarily
     * useful when you wish to pre-register extension objects. Note that if loading fails the provided Wallet object
     * may be in an indeterminate state and should be thrown away. Do not simply call this method again on the same
     * Wallet object with {@code forceReset} set {@code true}. It won't work.</p>
     *
     * <p>If {@code forceReset} is {@code true}, then no transactions are loaded from the wallet, and it is configured
     * to replay transactions from the blockchain (as if the wallet had been loaded and {@link Wallet#reset()}
     * had been called immediately thereafter).
     *
     * <p>A wallet can be unreadable for various reasons, such as inability to open the file, corrupt data, internally
     * inconsistent data, a wallet extension marked as mandatory that cannot be handled and so on. You should always
     * handle {@link UnreadableWalletException} and communicate failure to the user in an appropriate manner.</p>
     *
     * @throws UnreadableWalletException thrown in various error conditions (see description).
     */
    public Wallet readWallet(NetworkParameters params, @Nullable WalletExtension[] extensions,
                             Protos.Wallet walletProto, boolean forceReset) throws UnreadableWalletException {
        if (walletProto.getVersion() > CURRENT_WALLET_VERSION)
            throw new UnreadableWalletException.FutureVersion();
        if (!walletProto.getNetworkIdentifier().equals(params.getId()))
            throw new UnreadableWalletException.WrongNetwork();

        // Read the scrypt parameters that specify how encryption and decryption is performed.
        KeyChainGroup keyChainGroup;
        if (walletProto.hasEncryptionParameters()) {
            Protos.ScryptParameters encryptionParameters = walletProto.getEncryptionParameters();
            final KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(encryptionParameters);
            keyChainGroup = KeyChainGroup.fromProtobufEncrypted(params, walletProto.getKeyList(), keyCrypter, keyChainFactory);
        } else {
            keyChainGroup = KeyChainGroup.fromProtobufUnencrypted(params, walletProto.getKeyList(), keyChainFactory);
        }
        Wallet wallet = factory.create(params, keyChainGroup);

        List<Script> scripts = Lists.newArrayList();
        for (Protos.Script protoScript : walletProto.getWatchedScriptList()) {
            try {
                Script script =
                        new Script(protoScript.getProgram().toByteArray(),
                                protoScript.getCreationTimestamp() / 1000);
                scripts.add(script);
            } catch (ScriptException e) {
                throw new UnreadableWalletException("Unparseable script in wallet");
            }
        }

        wallet.addWatchedScripts(scripts);

        if (walletProto.hasDescription()) {
            wallet.setDescription(walletProto.getDescription());
        }

        if (forceReset) {
            // Should mirror Wallet.reset()
            wallet.setLastBlockSeenHash(null);
            wallet.setLastBlockSeenHeight(-1);
            wallet.setLastBlockSeenTimeSecs(0);
        } else {
            // Read all transactions and insert into the txMap.
            for (Protos.Transaction txProto : walletProto.getTransactionList()) {
                readTransaction(txProto, wallet.getParams());
            }

            // Update transaction outputs to point to inputs that spend them
            for (Protos.Transaction txProto : walletProto.getTransactionList()) {
                WalletTransaction wtx = connectTransactionOutputs(params, txProto);
                wallet.addWalletTransaction(wtx);
            }

            // Update the lastBlockSeenHash.
            if (!walletProto.hasLastSeenBlockHash()) {
                wallet.setLastBlockSeenHash(null);
            } else {
                wallet.setLastBlockSeenHash(byteStringToHash(walletProto.getLastSeenBlockHash()));
            }
            if (!walletProto.hasLastSeenBlockHeight()) {
                wallet.setLastBlockSeenHeight(-1);
            } else {
                wallet.setLastBlockSeenHeight(walletProto.getLastSeenBlockHeight());
            }
            // Will default to zero if not present.
            wallet.setLastBlockSeenTimeSecs(walletProto.getLastSeenBlockTimeSecs());

            if (walletProto.hasKeyRotationTime()) {
                wallet.setKeyRotationTime(new Date(walletProto.getKeyRotationTime() * 1000));
            }
        }

        loadExtensions(wallet, extensions != null ? extensions : new WalletExtension[0], walletProto);

        for (Protos.Tag tag : walletProto.getTagsList()) {
            wallet.setTag(tag.getTag(), tag.getData());
        }

        for (Protos.TransactionSigner signerProto : walletProto.getTransactionSignersList()) {
            try {
                Class signerClass = Class.forName(signerProto.getClassName());
                TransactionSigner signer = (TransactionSigner)signerClass.newInstance();
                signer.deserialize(signerProto.getData().toByteArray());
                wallet.addTransactionSigner(signer);
            } catch (Exception e) {
                throw new UnreadableWalletException("Unable to deserialize TransactionSigner instance: " +
                        signerProto.getClassName(), e);
            }
        }

        if (walletProto.hasVersion()) {
            wallet.setVersion(walletProto.getVersion());
        }

        // Make sure the object can be re-used to read another wallet without corruption.
        txMap.clear();

        return wallet;
    }

    private void loadExtensions(Wallet wallet, WalletExtension[] extensionsList, Protos.Wallet walletProto) throws UnreadableWalletException {
        final Map<String, WalletExtension> extensions = new HashMap<>();
        for (WalletExtension e : extensionsList)
            extensions.put(e.getWalletExtensionID(), e);
        // The Wallet object, if subclassed, might have added some extensions to itself already. In that case, don't
        // expect them to be passed in, just fetch them here and don't re-add.
        extensions.putAll(wallet.getExtensions());
        for (Protos.Extension extProto : walletProto.getExtensionList()) {
            String id = extProto.getId();
            WalletExtension extension = extensions.get(id);
            if (extension == null) {
                if (extProto.getMandatory()) {
                    if (requireMandatoryExtensions)
                        throw new UnreadableWalletException("Unknown mandatory extension in wallet: " + id);
                    else
                        log.error("Unknown extension in wallet {}, ignoring", id);
                } else if (requireAllExtensionsKnown) {
                    throw new UnreadableWalletException("Unknown extension in wallet: " + id);
                }
            } else {
                log.info("Loading wallet extension {}", id);
                try {
                    wallet.deserializeExtension(extension, extProto.getData().toByteArray());
                } catch (Exception e) {
                    if (extProto.getMandatory() && requireMandatoryExtensions) {
                        log.error("Error whilst reading mandatory extension {}, failing to read wallet", id);
                        throw new UnreadableWalletException("Could not parse mandatory extension in wallet: " + id);
                    } else if (requireAllExtensionsKnown) {
                        log.error("Error whilst reading extension {}, failing to read wallet", id);
                        throw new UnreadableWalletException("Could not parse extension in wallet: " + id);
                    } else {
                        log.warn("Error whilst reading extension {}, ignoring extension", id, e);
                    }
                }
            }
        }
    }

    /**
     * Returns the loaded protocol buffer from the given byte stream. You normally want
     * {@link Wallet#loadFromFile(java.io.File, WalletExtension...)} instead - this method is designed for low level
     * work involving the wallet file format itself.
     */
    public static Protos.Wallet parseToProto(InputStream input) throws IOException {
        CodedInputStream codedInput = CodedInputStream.newInstance(input);
        codedInput.setSizeLimit(WALLET_SIZE_LIMIT);
        return Protos.Wallet.parseFrom(codedInput);
    }

    private void readTransaction(Protos.Transaction txProto, NetworkParameters params) throws UnreadableWalletException {
        Transaction tx = new Transaction(params);

        tx.setVersion(txProto.getVersion());

        if (txProto.hasUpdatedAt()) {
            tx.setUpdateTime(new Date(txProto.getUpdatedAt()));
        }

        for (Protos.TransactionOutput outputProto : txProto.getTransactionOutputList()) {
            Coin value = Coin.valueOf(outputProto.getValue());
            byte[] scriptBytes = outputProto.getScriptBytes().toByteArray();
            TransactionOutput output = new TransactionOutput(params, tx, value, scriptBytes);
            tx.addOutput(output);
        }

        for (Protos.TransactionInput inputProto : txProto.getTransactionInputList()) {
            byte[] scriptBytes = inputProto.getScriptBytes().toByteArray();
            TransactionOutPoint outpoint = new TransactionOutPoint(params,
                    inputProto.getTransactionOutPointIndex() & 0xFFFFFFFFL,
                    byteStringToHash(inputProto.getTransactionOutPointHash())
            );
            Coin value = inputProto.hasValue() ? Coin.valueOf(inputProto.getValue()) : null;
            TransactionInput input = new TransactionInput(params, tx, scriptBytes, outpoint, value);
            if (inputProto.hasSequence())
                input.setSequenceNumber(0xffffffffL & inputProto.getSequence());
            tx.addInput(input);
        }

        for (int i = 0; i < txProto.getTransactionInputCount(); i++) {
            Protos.ScriptWitness witnessProto = txProto.getTransactionInput(i).getWitness();
            if (witnessProto.getDataCount() > 0) {
                TransactionWitness witness = new TransactionWitness(witnessProto.getDataCount());
                for(int j = 0; j < witnessProto.getDataCount(); j++) {
                    witness.setPush(j, witnessProto.getData(j).toByteArray());
                }
                tx.setWitness(i, witness);
            }
        }

        for (int i = 0; i < txProto.getBlockHashCount(); i++) {
            ByteString blockHash = txProto.getBlockHash(i);
            int relativityOffset = 0;
            if (txProto.getBlockRelativityOffsetsCount() > 0)
                relativityOffset = txProto.getBlockRelativityOffsets(i);
            tx.addBlockAppearance(byteStringToHash(blockHash), relativityOffset);
        }

        if (txProto.hasLockTime()) {
            tx.setLockTime(0xffffffffL & txProto.getLockTime());
        }

        if (txProto.hasPurpose()) {
            switch (txProto.getPurpose()) {
                case UNKNOWN: tx.setPurpose(Transaction.Purpose.UNKNOWN); break;
                case USER_PAYMENT: tx.setPurpose(Transaction.Purpose.USER_PAYMENT); break;
                case KEY_ROTATION: tx.setPurpose(Transaction.Purpose.KEY_ROTATION); break;
                case ASSURANCE_CONTRACT_CLAIM: tx.setPurpose(Transaction.Purpose.ASSURANCE_CONTRACT_CLAIM); break;
                case ASSURANCE_CONTRACT_PLEDGE: tx.setPurpose(Transaction.Purpose.ASSURANCE_CONTRACT_PLEDGE); break;
                case ASSURANCE_CONTRACT_STUB: tx.setPurpose(Transaction.Purpose.ASSURANCE_CONTRACT_STUB); break;
                case RAISE_FEE: tx.setPurpose(Transaction.Purpose.RAISE_FEE); break;
                default: throw new RuntimeException("New purpose serialization not implemented");
            }
        } else {
            // Old wallet: assume a user payment as that's the only reason a new tx would have been created back then.
            tx.setPurpose(Transaction.Purpose.USER_PAYMENT);
        }

        if (txProto.hasExchangeRate()) {
            Protos.ExchangeRate exchangeRateProto = txProto.getExchangeRate();
            tx.setExchangeRate(new ExchangeRate(Coin.valueOf(exchangeRateProto.getCoinValue()), Fiat.valueOf(
                    exchangeRateProto.getFiatCurrencyCode(), exchangeRateProto.getFiatValue())));
        }

        if (txProto.hasMemo())
            tx.setMemo(txProto.getMemo());

        // Transaction should now be complete.
        Sha256Hash protoHash = byteStringToHash(txProto.getHash());
        if (!tx.getHash().equals(protoHash))
            throw new UnreadableWalletException(String.format(Locale.US, "Transaction did not deserialize completely: %s vs %s", tx.getHash(), protoHash));
        if (txMap.containsKey(txProto.getHash()))
            throw new UnreadableWalletException("Wallet contained duplicate transaction " + byteStringToHash(txProto.getHash()));
        txMap.put(txProto.getHash(), tx);
    }

    private WalletTransaction connectTransactionOutputs(final NetworkParameters params,
                                                        final org.bitcoinj.wallet.Protos.Transaction txProto) throws UnreadableWalletException {
        Transaction tx = txMap.get(txProto.getHash());
        final WalletTransaction.Pool pool;
        switch (txProto.getPool()) {
            case DEAD: pool = WalletTransaction.Pool.DEAD; break;
            case PENDING: pool = WalletTransaction.Pool.PENDING; break;
            case SPENT: pool = WalletTransaction.Pool.SPENT; break;
            case UNSPENT: pool = WalletTransaction.Pool.UNSPENT; break;
            // Upgrade old wallets: inactive pool has been merged with the pending pool.
            // Remove this some time after 0.9 is old and everyone has upgraded.
            // There should not be any spent outputs in this tx as old wallets would not allow them to be spent
            // in this state.
            case INACTIVE:
            case PENDING_INACTIVE:
                pool = WalletTransaction.Pool.PENDING;
                break;
            default:
                throw new UnreadableWalletException("Unknown transaction pool: " + txProto.getPool());
        }
        for (int i = 0 ; i < tx.getOutputs().size() ; i++) {
            TransactionOutput output = tx.getOutputs().get(i);
            final Protos.TransactionOutput transactionOutput = txProto.getTransactionOutput(i);
            if (transactionOutput.hasSpentByTransactionHash()) {
                final ByteString spentByTransactionHash = transactionOutput.getSpentByTransactionHash();
                Transaction spendingTx = txMap.get(spentByTransactionHash);
                if (spendingTx == null) {
                    throw new UnreadableWalletException(String.format(Locale.US, "Could not connect %s to %s",
                            tx.getHashAsString(), byteStringToHash(spentByTransactionHash)));
                }
                final int spendingIndex = transactionOutput.getSpentByTransactionIndex();
                TransactionInput input = checkNotNull(spendingTx.getInput(spendingIndex));
                input.connect(output);
            }
        }

        if (txProto.hasConfidence()) {
            Protos.TransactionConfidence confidenceProto = txProto.getConfidence();
            TransactionConfidence confidence = tx.getConfidence();
            readConfidence(params, tx, confidenceProto, confidence);
        }

        return new WalletTransaction(pool, tx);
    }

    private void readConfidence(final NetworkParameters params, final Transaction tx,
                                final Protos.TransactionConfidence confidenceProto,
                                final TransactionConfidence confidence) throws UnreadableWalletException {
        // We are lenient here because tx confidence is not an essential part of the wallet.
        // If the tx has an unknown type of confidence, ignore.
        if (!confidenceProto.hasType()) {
            log.warn("Unknown confidence type for tx {}", tx.getHashAsString());
            return;
        }
        ConfidenceType confidenceType;
        switch (confidenceProto.getType()) {
            case BUILDING: confidenceType = ConfidenceType.BUILDING; break;
            case DEAD: confidenceType = ConfidenceType.DEAD; break;
            // These two are equivalent (must be able to read old wallets).
            case NOT_IN_BEST_CHAIN: confidenceType = ConfidenceType.PENDING; break;
            case PENDING: confidenceType = ConfidenceType.PENDING; break;
            case IN_CONFLICT: confidenceType = ConfidenceType.IN_CONFLICT; break;
            case UNKNOWN:
                // Fall through.
            default:
                confidenceType = ConfidenceType.UNKNOWN; break;
        }
        confidence.setConfidenceType(confidenceType);
        if (confidenceProto.hasAppearedAtHeight()) {
            if (confidence.getConfidenceType() != ConfidenceType.BUILDING) {
                log.warn("Have appearedAtHeight but not BUILDING for tx {}", tx.getHashAsString());
                return;
            }
            confidence.setAppearedAtChainHeight(confidenceProto.getAppearedAtHeight());
        }
        if (confidenceProto.hasDepth()) {
            if (confidence.getConfidenceType() != ConfidenceType.BUILDING) {
                log.warn("Have depth but not BUILDING for tx {}", tx.getHashAsString());
                return;
            }
            confidence.setDepthInBlocks(confidenceProto.getDepth());
        }
        if (confidenceProto.hasOverridingTransaction()) {
            if (confidence.getConfidenceType() != ConfidenceType.DEAD) {
                log.warn("Have overridingTransaction but not OVERRIDDEN for tx {}", tx.getHashAsString());
                return;
            }
            Transaction overridingTransaction =
                txMap.get(confidenceProto.getOverridingTransaction());
            if (overridingTransaction == null) {
                log.warn("Have overridingTransaction that is not in wallet for tx {}", tx.getHashAsString());
                return;
            }
            confidence.setOverridingTransaction(overridingTransaction);
        }
        for (Protos.PeerAddress proto : confidenceProto.getBroadcastByList()) {
            InetAddress ip;
            try {
                ip = InetAddress.getByAddress(proto.getIpAddress().toByteArray());
            } catch (UnknownHostException e) {
                throw new UnreadableWalletException("Peer IP address does not have the right length", e);
            }
            int port = proto.getPort();
            int protocolVersion = params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT);
            BigInteger services = BigInteger.valueOf(proto.getServices());
            PeerAddress address = new PeerAddress(params, ip, port, protocolVersion, services);
            confidence.markBroadcastBy(address);
        }
        if (confidenceProto.hasLastBroadcastedAt())
            confidence.setLastBroadcastedAt(new Date(confidenceProto.getLastBroadcastedAt()));
        switch (confidenceProto.getSource()) {
            case SOURCE_SELF: confidence.setSource(TransactionConfidence.Source.SELF); break;
            case SOURCE_NETWORK: confidence.setSource(TransactionConfidence.Source.NETWORK); break;
            case SOURCE_UNKNOWN:
                // Fall through.
            default: confidence.setSource(TransactionConfidence.Source.UNKNOWN); break;
        }
    }

    /**
     * Cheap test to see if input stream is a wallet. This checks for a magic value at the beginning of the stream.
     *
     * @param is
     *            input stream to test
     * @return true if input stream is a wallet
     */
    public static boolean isWallet(InputStream is) {
        try {
            final CodedInputStream cis = CodedInputStream.newInstance(is);
            final int tag = cis.readTag();
            final int field = WireFormat.getTagFieldNumber(tag);
            if (field != 1) // network_identifier
                return false;
            final String network = cis.readString();
            return NetworkParameters.fromID(network) != null;
        } catch (IOException x) {
            return false;
        }
    }
}
