/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.tools;

import org.bitcoinj.core.listeners.NewBestBlockListener;
import org.bitcoinj.core.*;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import com.google.common.io.Resources;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Future;

import static com.google.common.base.Preconditions.checkState;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Downloads and verifies a full chain from your local peer, emitting checkpoints at each difficulty transition period
 * to a file which is then signed with your key.
 */
public class BuildCheckpoints {
    private static NetworkParameters params;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.initWithSilentBitcoinJ();

        OptionParser parser = new OptionParser();
        parser.accepts("help");
        OptionSpec<NetworkEnum> netFlag = parser.accepts("net").withRequiredArg().ofType(NetworkEnum.class).defaultsTo(NetworkEnum.MAIN);
        parser.accepts("peer").withRequiredArg();
        OptionSpec<Integer> daysFlag = parser.accepts("days").withRequiredArg().ofType(Integer.class).defaultsTo(30);
        OptionSet options = parser.parse(args);

        if (options.has("help")) {
            System.out.println(Resources.toString(BuildCheckpoints.class.getResource("build-checkpoints-help.txt"), StandardCharsets.UTF_8));
            return;
        }

        final String suffix;
        switch (netFlag.value(options)) {
            case MAIN:
            case PROD:
                params = MainNetParams.get();
                suffix = "";
                break;
            case TEST:
                params = TestNet3Params.get();
                suffix = "-testnet";
                break;
            case REGTEST:
                params = RegTestParams.get();
                suffix = "-regtest";
                break;
            default:
                throw new RuntimeException("Unreachable.");
        }

        // Configure bitcoinj to fetch only headers, not save them to disk, connect to a local fully synced/validated
        // node and to save block headers that are on interval boundaries, as long as they are <1 month old.
        final BlockStore store = new MemoryBlockStore(params);
        final BlockChain chain = new BlockChain(params, store);
        final PeerGroup peerGroup = new PeerGroup(params, chain);

        final InetAddress ipAddress;

        // DNS discovery can be used for some networks
        boolean networkHasDnsSeeds = params.getDnsSeeds() != null;
        if (options.has("peer")) {
            // use peer provided in argument
            String peerFlag = (String) options.valueOf("peer");
            try {
                ipAddress = InetAddress.getByName(peerFlag);
                startPeerGroup(peerGroup, ipAddress);
            } catch (UnknownHostException e) {
                System.err.println("Could not understand peer domain name/IP address: " + peerFlag + ": " + e.getMessage());
                System.exit(1);
                return;
            }
        } else if (networkHasDnsSeeds) {
            // for PROD and TEST use a peer group discovered with dns
            peerGroup.setUserAgent("PeerMonitor", "1.0");
            peerGroup.setMaxConnections(20);
            peerGroup.addPeerDiscovery(new DnsDiscovery(params));
            peerGroup.start();

            // Connect to at least 4 peers because some may not support download
            Future<List<Peer>> future = peerGroup.waitForPeers(4);
            System.out.println("Connecting to " + params.getId() + ", timeout 20 seconds...");
            // throw timeout exception if we can't get peers
            future.get(20, SECONDS);
        } else {
            // try localhost
            ipAddress = InetAddress.getLocalHost();
            startPeerGroup(peerGroup, ipAddress);
        }

        // Sorted map of block height to StoredBlock object.
        final TreeMap<Integer, StoredBlock> checkpoints = new TreeMap<Integer, StoredBlock>();

        long now = new Date().getTime() / 1000;
        peerGroup.setFastCatchupTimeSecs(now);

        final long timeAgo = now - (86400 * options.valueOf(daysFlag));
        System.out.println("Checkpointing up to " + Utils.dateTimeFormat(timeAgo * 1000));

        chain.addNewBestBlockListener(Threading.SAME_THREAD, new NewBestBlockListener() {
            @Override
            public void notifyNewBestBlock(StoredBlock block) throws VerificationException {
                int height = block.getHeight();
                if (height % params.getInterval() == 0 && block.getHeader().getTimeSeconds() <= timeAgo) {
                    System.out.println(String.format("Checkpointing block %s at height %d, time %s",
                            block.getHeader().getHash(), block.getHeight(), Utils.dateTimeFormat(block.getHeader().getTime())));
                    checkpoints.put(height, block);
                }
            }
        });

        peerGroup.downloadBlockChain();

        checkState(checkpoints.size() > 0);

        final File plainFile = new File("checkpoints" + suffix);
        final File textFile = new File("checkpoints" + suffix + ".txt");

        // Write checkpoint data out.
        writeBinaryCheckpoints(checkpoints, plainFile);
        writeTextualCheckpoints(checkpoints, textFile);

        peerGroup.stop();
        store.close();

        // Sanity check the created files.
        sanityCheck(plainFile, checkpoints.size());
        sanityCheck(textFile, checkpoints.size());
    }

    private static void writeBinaryCheckpoints(TreeMap<Integer, StoredBlock> checkpoints, File file) throws Exception {
        final FileOutputStream fileOutputStream = new FileOutputStream(file, false);
        MessageDigest digest = Sha256Hash.newDigest();
        final DigestOutputStream digestOutputStream = new DigestOutputStream(fileOutputStream, digest);
        digestOutputStream.on(false);
        final DataOutputStream dataOutputStream = new DataOutputStream(digestOutputStream);
        dataOutputStream.writeBytes("CHECKPOINTS 1");
        dataOutputStream.writeInt(0);  // Number of signatures to read. Do this later.
        digestOutputStream.on(true);
        dataOutputStream.writeInt(checkpoints.size());
        ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
        for (StoredBlock block : checkpoints.values()) {
            block.serializeCompact(buffer);
            dataOutputStream.write(buffer.array());
            buffer.position(0);
        }
        dataOutputStream.close();
        Sha256Hash checkpointsHash = Sha256Hash.wrap(digest.digest());
        System.out.println("Hash of checkpoints data is " + checkpointsHash);
        digestOutputStream.close();
        fileOutputStream.close();
        System.out.println("Checkpoints written to '" + file.getCanonicalPath() + "'.");
    }

    private static void writeTextualCheckpoints(TreeMap<Integer, StoredBlock> checkpoints, File file) throws IOException {
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.US_ASCII));
        writer.println("TXT CHECKPOINTS 1");
        writer.println("0"); // Number of signatures to read. Do this later.
        writer.println(checkpoints.size());
        ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
        for (StoredBlock block : checkpoints.values()) {
            block.serializeCompact(buffer);
            writer.println(CheckpointManager.BASE64.encode(buffer.array()));
            buffer.position(0);
        }
        writer.close();
        System.out.println("Checkpoints written to '" + file.getCanonicalPath() + "'.");
    }

    private static void sanityCheck(File file, int expectedSize) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        CheckpointManager manager;
        try {
            manager = new CheckpointManager(params, fis);
        } finally {
            fis.close();
        }

        checkState(manager.numCheckpoints() == expectedSize);

        if (params.getId().equals(NetworkParameters.ID_MAINNET)) {
            StoredBlock test = manager.getCheckpointBefore(1390500000); // Thu Jan 23 19:00:00 CET 2014
            checkState(test.getHeight() == 280224);
            checkState(test.getHeader().getHashAsString()
                    .equals("00000000000000000b5d59a15f831e1c45cb688a4db6b0a60054d49a9997fa34"));
        } else if (params.getId().equals(NetworkParameters.ID_TESTNET)) {
            StoredBlock test = manager.getCheckpointBefore(1390500000); // Thu Jan 23 19:00:00 CET 2014
            checkState(test.getHeight() == 167328);
            checkState(test.getHeader().getHashAsString()
                    .equals("0000000000035ae7d5025c2538067fe7adb1cf5d5d9c31b024137d9090ed13a9"));
        }
    }

    private static void startPeerGroup(PeerGroup peerGroup, InetAddress ipAddress) {
        final PeerAddress peerAddress = new PeerAddress(params, ipAddress);
        System.out.println("Connecting to " + peerAddress + "...");
        peerGroup.addAddress(peerAddress);
        peerGroup.start();
    }
}
