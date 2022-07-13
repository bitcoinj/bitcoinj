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

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.params.AbstractBitcoinNetParams;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.SigNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.protocols.payments.PaymentProtocol;
import org.bitcoinj.script.Script;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.base.utils.MonetaryFormat;
import org.bitcoinj.utils.VersionTally;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * <p>NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.</p>
 *
 * <p>This is an abstract class, concrete instantiations can be found in the params package. There are four:
 * one for the main network ({@link MainNetParams}), one for the public test network, and two others that are
 * intended for unit testing and local app development purposes. Although this class contains some aliases for
 * them, you are encouraged to call the static get() methods on each specific params class directly.</p>
 */
public abstract class NetworkParameters {

    /** The string used by the payment protocol to represent the main net. */
    @Deprecated
    public static final String PAYMENT_PROTOCOL_ID_MAINNET = PaymentProtocol.PAYMENT_PROTOCOL_ID_MAINNET;
    /** The string used by the payment protocol to represent the test net. */
    @Deprecated
    public static final String PAYMENT_PROTOCOL_ID_TESTNET = PaymentProtocol.PAYMENT_PROTOCOL_ID_TESTNET;
    /** The string used by the payment protocol to represent signet (note that this is non-standard). */
    @Deprecated
    public static final String PAYMENT_PROTOCOL_ID_SIGNET = PaymentProtocol.PAYMENT_PROTOCOL_ID_SIGNET;
    /** The string used by the payment protocol to represent unit testing (note that this is non-standard). */
    @Deprecated
    public static final String PAYMENT_PROTOCOL_ID_UNIT_TESTS = PaymentProtocol.PAYMENT_PROTOCOL_ID_UNIT_TESTS;
    @Deprecated
    public static final String PAYMENT_PROTOCOL_ID_REGTEST = PaymentProtocol.PAYMENT_PROTOCOL_ID_REGTEST;

    // TODO: Seed nodes should be here as well.

    protected BigInteger maxTarget;
    protected int port;
    protected long packetMagic;  // Indicates message origin network and is used to seek to the next message when stream state is unknown.
    protected int addressHeader;
    protected int p2shHeader;
    protected int dumpedPrivateKeyHeader;
    protected String segwitAddressHrp;
    protected int interval;
    protected int targetTimespan;
    protected int bip32HeaderP2PKHpub;
    protected int bip32HeaderP2PKHpriv;
    protected int bip32HeaderP2WPKHpub;
    protected int bip32HeaderP2WPKHpriv;

    /** Used to check majorities for block version upgrade */
    protected int majorityEnforceBlockUpgrade;
    protected int majorityRejectBlockOutdated;
    protected int majorityWindow;

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    protected String id;
    protected final BitcoinNetwork network;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    protected int spendableCoinbaseDepth;
    protected int subsidyDecreaseBlockCount;
    
    protected String[] dnsSeeds;
    protected int[] addrSeeds;
    protected Map<Integer, Sha256Hash> checkpoints = new HashMap<>();
    protected volatile transient MessageSerializer defaultSerializer = null;

    protected NetworkParameters(BitcoinNetwork network) {
        this.network = network;
    }

    public static final int TARGET_TIMESPAN = 14 * 24 * 60 * 60;  // 2 weeks per difficulty cycle, on average.
    public static final int TARGET_SPACING = 10 * 60;  // 10 minutes per block.
    public static final int INTERVAL = TARGET_TIMESPAN / TARGET_SPACING;
    
    /**
     * Blocks with a timestamp after this should enforce BIP 16, aka "Pay to script hash". This BIP changed the
     * network rules in a soft-forking manner, that is, blocks that don't follow the rules are accepted but not
     * mined upon and thus will be quickly re-orged out as long as the majority are enforcing the rule.
     */
    public static final int BIP16_ENFORCE_TIME = 1333238400;
    
    /**
     * The maximum number of coins to be generated
     * @deprecated Use {@link BitcoinNetwork#MAX_MONEY}
     */
    @Deprecated
    public static final long MAX_COINS = BitcoinNetwork.MAX_MONEY.longValue();

    /**
     * The maximum money to be generated
     * @deprecated Use {@link BitcoinNetwork#MAX_MONEY}
     */
    @Deprecated
    public static final Coin MAX_MONEY = BitcoinNetwork.MAX_MONEY;

    /**
     * A Java package style string acting as unique ID for these parameters
     * @return network id string
     */
    public String getId() {
        return id;
    }

    /**
     * @return Network enum for this network
     */
    public BitcoinNetwork network() {
        return network;
    }

    /**
     * @return the payment protocol network id string
     * @deprecated Use {@link PaymentProtocol#protocolIdFromParams(NetworkParameters)}
     */
    @Deprecated
    public abstract String getPaymentProtocolId();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return getId().equals(((NetworkParameters)o).getId());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId());
    }

    /**
     * Return network parameters for a network id
     * @param id the network id
     * @return the network parameters for the given string ID or NULL if not recognized
     * @deprecated Use {@link AbstractBitcoinNetParams#fromID(String)}
     */
    @Deprecated
    @Nullable
    public static NetworkParameters fromID(String id) {
        return AbstractBitcoinNetParams.fromID(id);
    }

    /**
     * Return network parameters for a {@link BitcoinNetwork} enum
     * @param network the network
     * @return the network parameters for the given string ID
     * @throws IllegalArgumentException if unknown network
     */
    public static NetworkParameters of(BitcoinNetwork network) {
        switch (network) {
            case MAINNET:
                return MainNetParams.get();
            case TESTNET:
                return TestNet3Params.get();
            case SIGNET:
                return SigNetParams.get();
            case REGTEST:
                return RegTestParams.get();
            default:
                throw new IllegalArgumentException("Unknown network");
        }
    }

    /**
     * Return network parameters for a paymentProtocol ID string
     * @param pmtProtocolId paymentProtocol ID string
     * @return network parameters for the given string paymentProtocolID or NULL if not recognized
     * @deprecated Use {@link PaymentProtocol#paramsFromPmtProtocolID(String)} (String)}
     */
    @Nullable
    @Deprecated
    public static NetworkParameters fromPmtProtocolID(String pmtProtocolId) {
        return PaymentProtocol.paramsFromPmtProtocolID(pmtProtocolId);
    }

    /**
     * Get a NetworkParameters from an Address.
     * Addresses should not be used for storing NetworkParameters. In the future Address will
     * be an {@code interface} that only makes a {@link BitcoinNetwork} available.
     * @param address An address
     * @return network parameters
     * @deprecated You should be using {@link Address#network()} instead
     */
    @Deprecated
    public static NetworkParameters fromAddress(Address address) {
        return address.getParameters();
    }

    public int getSpendableCoinbaseDepth() {
        return spendableCoinbaseDepth;
    }

    /**
     * Throws an exception if the block's difficulty is not correct.
     *
     * @param storedPrev previous stored block
     * @param next proposed block
     * @param blockStore active BlockStore
     * @throws VerificationException if the block's difficulty is not correct.
     * @throws BlockStoreException if an error occurred accessing the BlockStore
     */
    public abstract void checkDifficultyTransitions(StoredBlock storedPrev, Block next, final BlockStore blockStore) throws VerificationException, BlockStoreException;

    /**
     * Validate the hash for a given block height against checkpoints
     * @param height block height
     * @param hash hash for {@code height}
     * @return true if the block height is either not a checkpoint, or is a checkpoint and the hash matches
     */
    public boolean passesCheckpoint(int height, Sha256Hash hash) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash == null || checkpointHash.equals(hash);
    }

    /**
     * Is height a checkpoint
     * @param height block height
     * @return true if the given height has a recorded checkpoint
     */
    public boolean isCheckpoint(int height) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash != null;
    }

    public int getSubsidyDecreaseBlockCount() {
        return subsidyDecreaseBlockCount;
    }

    /**
     * Return DNS names that when resolved, give IP addresses of active peers
     * @return an array of DNS names
     */
    public String[] getDnsSeeds() {
        return dnsSeeds;
    }

    /**
     * Return IP addresses of active peers
     * @return array of IP addresses
     */
    public int[] getAddrSeeds() {
        return addrSeeds;
    }

    /**
     * <p>Genesis block for this chain.</p>
     *
     * <p>The first block in every chain is a well known constant shared between all Bitcoin implementations. For a
     * block to be valid, it must be eventually possible to work backwards to the genesis block by following the
     * prevBlockHash pointers in the block headers.</p>
     *
     * <p>The genesis blocks for both test and main networks contain the timestamp of when they were created,
     * and a message in the coinbase transaction. It says, <i>"The Times 03/Jan/2009 Chancellor on brink of second
     * bailout for banks"</i>.</p>
     * @return genesis block
     */
    public abstract Block getGenesisBlock();

    /**
     * Default TCP port on which to connect to nodes
     * @return default port for this network
     */
    public int getPort() {
        return port;
    }

    /**
     * The header bytes that identify the start of a packet on this network.
     * @return header bytes as a long
     */
    public long getPacketMagic() {
        return packetMagic;
    }

    /**
     * First byte of a base58 encoded address. See {@link LegacyAddress}. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     * @return the header value
     */
    public int getAddressHeader() {
        return addressHeader;
    }

    /**
     * First byte of a base58 encoded P2SH address.  P2SH addresses are defined as part of BIP0013.
     * @return the header value
     */
    public int getP2SHHeader() {
        return p2shHeader;
    }

    /**
     * First byte of a base58 encoded dumped private key. See {@link DumpedPrivateKey}.
     * @return the header value
     */
    public int getDumpedPrivateKeyHeader() {
        return dumpedPrivateKeyHeader;
    }

    /**
     * Human-readable part of bech32 encoded segwit address.
     * @return the human-readable part value
     */
    public String getSegwitAddressHrp() {
        return segwitAddressHrp;
    }

    /**
     * How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
     * significantly different from this value, the network difficulty formula will produce a different value. Both
     * test and main Bitcoin networks use 2 weeks (1209600 seconds).
     * @return target timespan in seconds
     */
    public int getTargetTimespan() {
        return targetTimespan;
    }

    /**
     * If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks.
     * @return true if allowed
     */
    public boolean allowEmptyPeerChain() {
        return true;
    }

    /**
     * How many blocks pass between difficulty adjustment periods. Bitcoin standardises this to be 2016.
     * @return number of blocks
     */
    public int getInterval() {
        return interval;
    }

    /**
     * Maximum target represents the easiest allowable proof of work.
     * @return maximum target integer
     */
    public BigInteger getMaxTarget() {
        return maxTarget;
    }

    /**
     * Returns the 4 byte header for BIP32 wallet P2PKH - public key part.
     * @return the header value
     */
    public int getBip32HeaderP2PKHpub() {
        return bip32HeaderP2PKHpub;
    }

    /**
     * Returns the 4 byte header for BIP32 wallet P2PKH - private key part.
     * @return the header value
     */
    public int getBip32HeaderP2PKHpriv() {
        return bip32HeaderP2PKHpriv;
    }

    /**
     * Returns the 4 byte header for BIP32 wallet P2WPKH - public key part.
     * @return the header value
     */
    public int getBip32HeaderP2WPKHpub() {
        return bip32HeaderP2WPKHpub;
    }

    /**
     * Returns the 4 byte header for BIP32 wallet P2WPKH - private key part.
     * @return the header value
     */
    public int getBip32HeaderP2WPKHpriv() {
        return bip32HeaderP2WPKHpriv;
    }
    /**
     * Returns the number of coins that will be produced in total, on this
     * network. Where not applicable, a very large number of coins is returned
     * instead (e.g. the main coin issue for Dogecoin).
     * @return maximum number of coins for this network
     * @deprecated Use {@link Network#maxMoney()}
     */
    @Deprecated
    public abstract Coin getMaxMoney();

    /**
     * @return coin value
     * @deprecated use {@link TransactionOutput#getMinNonDustValue()}
     */
    @Deprecated
    public abstract Coin getMinNonDustOutput();

    /**
     * The monetary object for this currency.
     * @return formatting utility object
     * @deprecated Get one another way or construct your own {@link MonetaryFormat} as needed.
     */
    @Deprecated
    public abstract MonetaryFormat getMonetaryFormat();

    /**
     * Scheme part for URIs, for example "bitcoin".
     * @return a string with the "scheme" part
     * @deprecated Use {@link Network#uriScheme()}
     */
    @Deprecated
    public abstract String getUriScheme();

    /**
     * Returns whether this network has a maximum number of coins (finite supply) or
     * not. Always returns true for Bitcoin, but exists to be overridden for other
     * networks.
     * @return true if network has a fixed maximum number of coins
     * @deprecated Use {@link Network#hasMaxMoney()}
     */
    @Deprecated
    public abstract boolean hasMaxMoney();

    /**
     * Return the default serializer for this network. This is a shared serializer.
     * @return the default serializer for this network.
     */
    public final MessageSerializer getDefaultSerializer() {
        // Construct a default serializer if we don't have one
        if (null == this.defaultSerializer) {
            // Don't grab a lock unless we absolutely need it
            synchronized(this) {
                // Now we have a lock, double check there's still no serializer
                // and create one if so.
                if (null == this.defaultSerializer) {
                    // As the serializers are intended to be immutable, creating
                    // two due to a race condition should not be a problem, however
                    // to be safe we ensure only one exists for each network.
                    this.defaultSerializer = getSerializer(false);
                }
            }
        }
        return defaultSerializer;
    }

    /**
     * Construct and return a custom serializer.
     * @param parseRetain whether the serializer should retain the backing byte array of a message for fast re-serialization.
     * @return the serializer
     */
    public abstract BitcoinSerializer getSerializer(boolean parseRetain);

    /**
     * The number of blocks in the last {@link #getMajorityWindow()} blocks
     * at which to trigger a notice to the user to upgrade their client, where
     * the client does not understand those blocks.
     * @return number of blocks
     */
    public int getMajorityEnforceBlockUpgrade() {
        return majorityEnforceBlockUpgrade;
    }

    /**
     * The number of blocks in the last {@link #getMajorityWindow()} blocks
     * at which to enforce the requirement that all new blocks are of the
     * newer type (i.e. outdated blocks are rejected).
     * @return number of blocks
     */
    public int getMajorityRejectBlockOutdated() {
        return majorityRejectBlockOutdated;
    }

    /**
     * The sampling window from which the version numbers of blocks are taken
     * in order to determine if a new block version is now the majority.
     * @return number of blocks
     */
    public int getMajorityWindow() {
        return majorityWindow;
    }

    /**
     * The flags indicating which block validation tests should be applied to
     * the given block. Enables support for alternative blockchains which enable
     * tests based on different criteria.
     * 
     * @param block block to determine flags for.
     * @param height height of the block, if known, null otherwise. Returned
     * tests should be a safe subset if block height is unknown.
     * @param tally caching tally counter
     * @return the flags
     */
    public EnumSet<Block.VerifyFlag> getBlockVerificationFlags(final Block block,
            final VersionTally tally, final Integer height) {
        final EnumSet<Block.VerifyFlag> flags = EnumSet.noneOf(Block.VerifyFlag.class);

        if (block.isBIP34()) {
            final Integer count = tally.getCountAtOrAbove(Block.BLOCK_VERSION_BIP34);
            if (null != count && count >= getMajorityEnforceBlockUpgrade()) {
                flags.add(Block.VerifyFlag.HEIGHT_IN_COINBASE);
            }
        }
        return flags;
    }

    /**
     * The flags indicating which script validation tests should be applied to
     * the given transaction. Enables support for alternative blockchains which enable
     * tests based on different criteria.
     *
     * @param block block the transaction belongs to.
     * @param transaction to determine flags for.
     * @param tally caching tally counter
     * @param height height of the block, if known, null otherwise. Returned
     * tests should be a safe subset if block height is unknown.
     * @return the flags
     */
    public EnumSet<Script.VerifyFlag> getTransactionVerificationFlags(final Block block,
            final Transaction transaction, final VersionTally tally, final Integer height) {
        final EnumSet<Script.VerifyFlag> verifyFlags = EnumSet.noneOf(Script.VerifyFlag.class);
        if (block.getTimeSeconds() >= NetworkParameters.BIP16_ENFORCE_TIME)
            verifyFlags.add(Script.VerifyFlag.P2SH);

        // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4
        // blocks, when 75% of the network has upgraded:
        if (block.getVersion() >= Block.BLOCK_VERSION_BIP65 &&
            tally.getCountAtOrAbove(Block.BLOCK_VERSION_BIP65) > this.getMajorityEnforceBlockUpgrade()) {
            verifyFlags.add(Script.VerifyFlag.CHECKLOCKTIMEVERIFY);
        }

        return verifyFlags;
    }

    public abstract int getProtocolVersionNum(final ProtocolVersion version);

    public static enum ProtocolVersion {
        MINIMUM(70000),
        PONG(60001),
        BLOOM_FILTER(70000), // BIP37
        BLOOM_FILTER_BIP111(70011), // BIP111
        WITNESS_VERSION(70012),
        FEEFILTER(70013), // BIP133
        CURRENT(70013);

        private final int bitcoinProtocol;

        ProtocolVersion(final int bitcoinProtocol) {
            this.bitcoinProtocol = bitcoinProtocol;
        }

        public int getBitcoinProtocolVersion() {
            return bitcoinProtocol;
        }
    }
}
