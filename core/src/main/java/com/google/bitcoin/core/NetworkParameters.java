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

import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.math.BigInteger;

import static com.google.common.base.Preconditions.checkState;

// TODO: Refactor this after we stop supporting serialization compatibility to use subclasses and singletons.

/**
 * NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.<p>
 *
 * Currently there are only two, the production chain and the test chain. But in future as Bitcoin
 * evolves there may be more. You can create your own as long as they don't conflict.
 */
public class NetworkParameters implements Serializable {
    private static final long serialVersionUID = 3L;

    /**
     * The protocol version this library implements.
     */
    public static final int PROTOCOL_VERSION = 60001;

    /**
     * The alert signing key originally owned by Satoshi, and now passed on to Gavin along with a few others.
     */
    public static final byte[] SATOSHI_KEY = Hex.decode("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");

    /**
     * The string returned by getId() for the main, production network where people trade things.
     */
    public static final String ID_PRODNET = "org.bitcoin.production";
    /**
     * The string returned by getId() for the testnet.
     */
    public static final String ID_TESTNET = "org.bitcoin.test";

    // TODO: Seed nodes and checkpoint values should be here as well.

    /**
     * Genesis block for this chain.<p>
     *
     * The first block in every chain is a well known constant shared between all BitCoin implemenetations. For a
     * block to be valid, it must be eventually possible to work backwards to the genesis block by following the
     * prevBlockHash pointers in the block headers.<p>
     *
     * The genesis blocks for both test and prod networks contain the timestamp of when they were created,
     * and a message in the coinbase transaction. It says, <i>"The Times 03/Jan/2009 Chancellor on brink of second
     * bailout for banks"</i>.
     */
    public Block genesisBlock;
    /** What the easiest allowable proof of work should be. */
    public BigInteger proofOfWorkLimit;
    /** Default TCP port on which to connect to nodes. */
    public int port;
    /** The header bytes that identify the start of a packet on this network. */
    public long packetMagic;
    /**
     * First byte of a base58 encoded address. See {@link Address}. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     */
    public int addressHeader;
    /** First byte of a base58 encoded dumped private key. See {@link DumpedPrivateKey}. */
    public int dumpedPrivateKeyHeader;
    /** How many blocks pass between difficulty adjustment periods. BitCoin standardises this to be 2015. */
    public int interval;
    /**
     * How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
     * significantly different from this value, the network difficulty formula will produce a different value. Both
     * test and production Bitcoin networks use 2 weeks (1209600 seconds).
     */
    public int targetTimespan;
    /**
     * The key used to sign {@link AlertMessage}s. You can use {@link ECKey#verify(byte[], byte[], byte[])} to verify
     * signatures using it.
     */
    public byte[] alertSigningKey;

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    private String id;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    private int spendableCoinbaseDepth;

    /**
     * The version codes that prefix addresses which are acceptable on this network. Although Satoshi intended these to
     * be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the
     * address and to prevent accidentally sending coins across chains which would destroy them.
     */
    public int[] acceptableAddressCodes;

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
            t.addOutput(new TransactionOutput(n, t, scriptPubKeyBytes.toByteArray()));
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

    /** Sets up the given Networkparemets with testnet3 values. */
    private static NetworkParameters createTestNet3(NetworkParameters n) {
        // Genesis hash is 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
        n.proofOfWorkLimit = Utils.decodeCompactBits(0x1d00ffffL);
        n.packetMagic = 0x0b110907;
        n.port = 18333;
        n.addressHeader = 111;
        n.acceptableAddressCodes = new int[] { 111 };
        n.dumpedPrivateKeyHeader = 239;
        n.interval = INTERVAL;
        n.targetTimespan = TARGET_TIMESPAN;
        n.alertSigningKey = SATOSHI_KEY;
        n.genesisBlock = createGenesis(n);
        n.genesisBlock.setTime(1296688602L);
        n.genesisBlock.setDifficultyTarget(0x1d00ffffL);
        n.genesisBlock.setNonce(414098458);
        n.setSpendableCoinbaseDepth(100);
        n.id = ID_TESTNET;
        String genesisHash = n.genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
                genesisHash);
        return n;
    }

    /** Sets up the given NetworkParameters with testnet values. */
    private static NetworkParameters createTestNet(NetworkParameters n) {
        // Genesis hash is 0000000224b1593e3ff16a0e3b61285bbc393a39f78c8aa48c456142671f7110
        n.proofOfWorkLimit = Utils.decodeCompactBits(0x1d0fffffL);
        n.packetMagic = 0xfabfb5daL;
        n.port = 18333;
        n.addressHeader = 111;
        n.acceptableAddressCodes = new int[] { 111 };
        n.dumpedPrivateKeyHeader = 239;
        n.interval = INTERVAL;
        n.targetTimespan = TARGET_TIMESPAN;
        n.alertSigningKey = SATOSHI_KEY;
        n.genesisBlock = createGenesis(n);
        n.genesisBlock.setTime(1296688602L);
        n.genesisBlock.setDifficultyTarget(0x1d07fff8L);
        n.genesisBlock.setNonce(384568319);
        n.setSpendableCoinbaseDepth(100);
        n.id = ID_TESTNET;
        String genesisHash = n.genesisBlock.getHashAsString();
        checkState(genesisHash.equals("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"),
                genesisHash);
        return n;
    }

    /** The test chain created by Gavin. */
    public static NetworkParameters testNet() {
        NetworkParameters n = new NetworkParameters();
        return createTestNet(n);
    }

    /** The testnet3 chain created by Gavin, included in Bitcoin 0.7. */
    public static NetworkParameters testNet3() {
        NetworkParameters n = new NetworkParameters();
        return createTestNet3(n);
    }

    /** The primary BitCoin chain created by Satoshi. */
    public static NetworkParameters prodNet() {
        NetworkParameters n = new NetworkParameters();
        n.proofOfWorkLimit = Utils.decodeCompactBits(0x1d00ffffL);
        n.port = 8333;
        n.packetMagic = 0xf9beb4d9L;
        n.addressHeader = 0;
        n.acceptableAddressCodes = new int[] { 0 };
        n.dumpedPrivateKeyHeader = 128;
        n.interval = INTERVAL;
        n.targetTimespan = TARGET_TIMESPAN;
        n.alertSigningKey = SATOSHI_KEY;
        n.genesisBlock = createGenesis(n);
        n.genesisBlock.setDifficultyTarget(0x1d00ffffL);
        n.genesisBlock.setTime(1231006505L);
        n.genesisBlock.setNonce(2083236893);
        n.setSpendableCoinbaseDepth(100);
        n.id = ID_PRODNET;
        String genesisHash = n.genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
                genesisHash);
        return n;
    }

    /** Returns a testnet params modified to allow any difficulty target. */
    public static NetworkParameters unitTests() {
        NetworkParameters n = new NetworkParameters();
        n = createTestNet(n);
        n.proofOfWorkLimit = new BigInteger("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
        n.genesisBlock.setTime(System.currentTimeMillis() / 1000);
        n.genesisBlock.setDifficultyTarget(Block.EASIEST_DIFFICULTY_TARGET);
        n.genesisBlock.solve();
        n.interval = 10;
        n.targetTimespan = 200000000;  // 6 years. Just a very big number.
        n.setSpendableCoinbaseDepth(5);
        n.id = "com.google.bitcoin.unittest";
        return n;
    }

    /**
     * A java package style string acting as unique ID for these parameters
     */
    public String getId() {
        if (id == null) {
            // Migrate from old serialized wallets which lack the ID field. This code can eventually be deleted.
            if (port == 8333) {
                id = ID_PRODNET;
            } else if (port == 18333) {
                id = ID_TESTNET;
            }
        }
        return id;
    }

    public boolean equals(Object other) {
        if (!(other instanceof NetworkParameters)) return false;
        NetworkParameters o = (NetworkParameters) other;
        return o.getId().equals(getId());
    }

    /** Returns the network parameters for the given string ID or NULL if not recognized. */
    public static NetworkParameters fromID(String id) {
        if (id.equals(ID_PRODNET)) {
            return prodNet();
        } else if (id.equals(ID_TESTNET)) {
            return testNet();
        } else {
            return null;
        }
    }

    public int getSpendableCoinbaseDepth() {
        return spendableCoinbaseDepth;
    }

    public void setSpendableCoinbaseDepth(int coinbaseDepth) {
        this.spendableCoinbaseDepth = coinbaseDepth;
    }
}
