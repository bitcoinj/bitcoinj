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

import com.google.common.base.Objects;
import com.google.common.collect.Lists;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import static com.google.bitcoin.core.Utils.COIN;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.</p>
 *
 * <p></p>Currently there are only two, the production chain and the test chain. There is also a "unit test chain" which
 * is internal to bitcoinj and can't be used on a real network. In future there may be others. </p>
 */
public class NetworkParameters implements Serializable {
    private static final long serialVersionUID = 3L;

    /**
     * The protocol version this library implements.
     */
    public static final int PROTOCOL_VERSION = 70001;

    /**
     * The alert signing key originally owned by Satoshi, and now passed on to Gavin along with a few others.
     */
    public static final byte[] SATOSHI_KEY = Hex.decode("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_PRODNET = "org.bitcoin.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_TESTNET = "org.bitcoin.test";
    /** Unit test network. */
    static final String ID_UNITTESTNET = "com.google.bitcoin.unittest";

    // TODO: Seed nodes should be here as well.

    // TODO: Replace with getters and then finish making all these fields final.

    /**
     * <p>Genesis block for this chain.</p>
     *
     * <p>The first block in every chain is a well known constant shared between all Bitcoin implemenetations. For a
     * block to be valid, it must be eventually possible to work backwards to the genesis block by following the
     * prevBlockHash pointers in the block headers.</p>
     *
     * <p>The genesis blocks for both test and prod networks contain the timestamp of when they were created,
     * and a message in the coinbase transaction. It says, <i>"The Times 03/Jan/2009 Chancellor on brink of second
     * bailout for banks"</i>.</p>
     */
    public final Block genesisBlock;
    /** What the easiest allowable proof of work should be. */
    public /*final*/ BigInteger proofOfWorkLimit;
    /** Default TCP port on which to connect to nodes. */
    public final int port;
    /** The header bytes that identify the start of a packet on this network. */
    public final long packetMagic;
    /**
     * First byte of a base58 encoded address. See {@link Address}. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     */
    public final int addressHeader;
    /** First byte of a base58 encoded dumped private key. See {@link DumpedPrivateKey}. */
    public final int dumpedPrivateKeyHeader;
    /** How many blocks pass between difficulty adjustment periods. Bitcoin standardises this to be 2015. */
    public /*final*/ int interval;
    /**
     * How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
     * significantly different from this value, the network difficulty formula will produce a different value. Both
     * test and production Bitcoin networks use 2 weeks (1209600 seconds).
     */
    public final int targetTimespan;
    /**
     * The key used to sign {@link AlertMessage}s. You can use {@link ECKey#verify(byte[], byte[], byte[])} to verify
     * signatures using it.
     */
    public /*final*/ byte[] alertSigningKey;

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    private final String id;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    private final int spendableCoinbaseDepth;
    
    /**
     * Returns the number of blocks between subsidy decreases
     */
    private /*final*/ int subsidyDecreaseBlockCount;
    
    /**
     * If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks
     */
    boolean allowEmptyPeerChains;

    /**
     * The version codes that prefix addresses which are acceptable on this network. Although Satoshi intended these to
     * be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the
     * address and to prevent accidentally sending coins across chains which would destroy them.
     */
    public final int[] acceptableAddressCodes;

    /**
     * DNS names that when resolved, give active peers on the network. Used to bootstrap the P2P connectivity.
     */
    private final String[] dnsSeeds;


    /**
     * Block checkpoints are a safety mechanism that hard-codes the hashes of blocks at particular heights. Re-orgs
     * beyond this point will never be accepted. This field should be accessed using
     * {@link NetworkParameters#passesCheckpoint(int, Sha256Hash)} and {@link NetworkParameters#isCheckpoint(int)}.
     */
    public Map<Integer, Sha256Hash> checkpoints = new HashMap<Integer, Sha256Hash>();

    private NetworkParameters(int type) {
        alertSigningKey = SATOSHI_KEY;
        genesisBlock = createGenesis(this);
        if (type == 0) {
            // Production.
            interval = INTERVAL;
            targetTimespan = TARGET_TIMESPAN;
            proofOfWorkLimit = Utils.decodeCompactBits(0x1d00ffffL);
            acceptableAddressCodes = new int[] { 0 };
            dumpedPrivateKeyHeader = 128;
            addressHeader = 0;
            port = 8333;
            packetMagic = 0xf9beb4d9L;
            genesisBlock.setDifficultyTarget(0x1d00ffffL);
            genesisBlock.setTime(1231006505L);
            genesisBlock.setNonce(2083236893);
            id = ID_PRODNET;
            subsidyDecreaseBlockCount = 210000;
            allowEmptyPeerChains = false;
            spendableCoinbaseDepth = 100;
            String genesisHash = genesisBlock.getHashAsString();
            checkState(genesisHash.equals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
                    genesisHash);

            // This contains (at a minimum) the blocks which are not BIP30 compliant. BIP30 changed how duplicate
            // transactions are handled. Duplicated transactions could occur in the case where a coinbase had the same
            // extraNonce and the same outputs but appeared at different heights, and greatly complicated re-org handling.
            // Having these here simplifies block connection logic considerably.
            checkpoints.put(91722, new Sha256Hash("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"));
            checkpoints.put(91812, new Sha256Hash("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"));
            checkpoints.put(91842, new Sha256Hash("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"));
            checkpoints.put(91880, new Sha256Hash("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"));
            checkpoints.put(200000, new Sha256Hash("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"));

            dnsSeeds = new String[] {
                    "seed.bitcoin.sipa.be",        // Pieter Wuille
                    "dnsseed.bluematt.me",         // Matt Corallo
                    "dnsseed.bitcoin.dashjr.org",  // Luke Dashjr
                    "bitseed.xf2.org",             // Jeff Garzik
            };
        } else if (type == 3) {
            // Testnet3
            id = ID_TESTNET;
            // Genesis hash is 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
            packetMagic = 0x0b110907;
            interval = INTERVAL;
            targetTimespan = TARGET_TIMESPAN;
            proofOfWorkLimit = Utils.decodeCompactBits(0x1d00ffffL);
            port = 18333;
            addressHeader = 111;
            acceptableAddressCodes = new int[] { 111 };
            dumpedPrivateKeyHeader = 239;
            genesisBlock.setTime(1296688602L);
            genesisBlock.setDifficultyTarget(0x1d00ffffL);
            genesisBlock.setNonce(414098458);
            allowEmptyPeerChains = true;
            spendableCoinbaseDepth = 100;
            subsidyDecreaseBlockCount = 210000;
            String genesisHash = genesisBlock.getHashAsString();
            checkState(genesisHash.equals("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
                    genesisHash);

            dnsSeeds = new String[] {
                    "testnet-seed.bitcoin.petertodd.org",
                    "testnet-seed.bluematt.me"
            };
        } else if (type == 2) {
            id = ID_TESTNET;
            packetMagic = 0xfabfb5daL;
            port = 18333;
            addressHeader = 111;
            interval = INTERVAL;
            targetTimespan = TARGET_TIMESPAN;
            proofOfWorkLimit = Utils.decodeCompactBits(0x1d0fffffL);
            acceptableAddressCodes = new int[] { 111 };
            dumpedPrivateKeyHeader = 239;
            genesisBlock.setTime(1296688602L);
            genesisBlock.setDifficultyTarget(0x1d07fff8L);
            genesisBlock.setNonce(384568319);
            allowEmptyPeerChains = false;
            spendableCoinbaseDepth = 100;
            subsidyDecreaseBlockCount = 210000;
            String genesisHash = genesisBlock.getHashAsString();
            checkState(genesisHash.equals("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"),
                    genesisHash);
            dnsSeeds = null;
        } else if (type == -1) {
            id = ID_UNITTESTNET;
            packetMagic = 0x0b110907;
            addressHeader = 111;
            proofOfWorkLimit = new BigInteger("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
            genesisBlock.setTime(System.currentTimeMillis() / 1000);
            genesisBlock.setDifficultyTarget(Block.EASIEST_DIFFICULTY_TARGET);
            genesisBlock.solve();
            port = 18333;
            interval = 10;
            dumpedPrivateKeyHeader = 239;
            allowEmptyPeerChains = false;
            targetTimespan = 200000000;  // 6 years. Just a very big number.
            spendableCoinbaseDepth = 5;
            acceptableAddressCodes = new int[] { 111 };
            subsidyDecreaseBlockCount = 100;
            dnsSeeds = null;
        } else {
            throw new RuntimeException();
        }
    }

    private static Block createGenesis(NetworkParameters n) {
        Block genesisBlock = new Block(n);
        Transaction t = new Transaction(n);
        try {
            // A script containing the difficulty bits and the following message:
            //
            //   "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
            byte[] bytes = Hex.decode
                    ("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73");
            t.addInput(new TransactionInput(n, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode
                    ("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"));
            scriptPubKeyBytes.write(Script.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, Utils.toNanoCoins(50, 0), scriptPubKeyBytes.toByteArray()));
        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        genesisBlock.addTransaction(t);
        return genesisBlock;
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
     * The maximum money to be generated
     */
    public static final BigInteger MAX_MONEY = new BigInteger("21000000", 10).multiply(COIN);

    /** Returns whatever the latest testNet parameters are.  Use this rather than the versioned equivalents. */
    public static NetworkParameters testNet() {
        return testNet3();
    }

    private static NetworkParameters tn2;
    public synchronized static NetworkParameters testNet2() {
        if (tn2 == null) {
            tn2 = new NetworkParameters(2);
        }
        return tn2;
    }

    private static NetworkParameters tn3;
    public synchronized static NetworkParameters testNet3() {
        if (tn3 == null) {
            tn3 = new NetworkParameters(3);
        }
        return tn3;
    }

    private static NetworkParameters pn;
    /** The primary Bitcoin chain created by Satoshi. */
    public synchronized static NetworkParameters prodNet() {
        if (pn == null) {
            pn = new NetworkParameters(0);
        }
        return pn;
    }

    private static NetworkParameters ut;
    /** Returns a testnet params modified to allow any difficulty target. */
    public synchronized static NetworkParameters unitTests() {
        if (ut == null) {
            ut = new NetworkParameters(-1);
        }
        return ut;
    }

    /**
     * A Java package style string acting as unique ID for these parameters
     */
    public String getId() {
        return id;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof NetworkParameters)) return false;
        NetworkParameters o = (NetworkParameters) other;
        return o.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getId());
    }

    /** Returns the network parameters for the given string ID or NULL if not recognized. */
    public static NetworkParameters fromID(String id) {
        if (id.equals(ID_PRODNET)) {
            return prodNet();
        } else if (id.equals(ID_TESTNET)) {
            return testNet();
        } else if (id.equals(ID_UNITTESTNET)) {
            return unitTests();
        } else {
            return null;
        }
    }

    public int getSpendableCoinbaseDepth() {
        return spendableCoinbaseDepth;
    }

    /**
     * Returns true if the block height is either not a checkpoint, or is a checkpoint and the hash matches.
     */
    public boolean passesCheckpoint(int height, Sha256Hash hash) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash == null || checkpointHash.equals(hash);
    }

    /**
     * Returns true if the given height has a recorded checkpoint.
     */
    public boolean isCheckpoint(int height) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash != null;
    }

    public int getSubsidyDecreaseBlockCount() {
        return subsidyDecreaseBlockCount;
    }

    public void setSubsidyDecreaseBlockCount(int value) {
        subsidyDecreaseBlockCount = value;
    }

    /** Returns DNS names that when resolved, give IP addresses of active peers. */
    public String[] getDnsSeeds() {
        return dnsSeeds;
    }
}
