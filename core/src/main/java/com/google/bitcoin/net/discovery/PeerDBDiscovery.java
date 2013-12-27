/*
 * Copyright 2013 Matt Corallo
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

package com.google.bitcoin.net.discovery;

import com.google.bitcoin.core.*;
import com.google.common.annotations.VisibleForTesting;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static com.google.common.base.Preconditions.checkState;

/**
 * Keeps a database of peers and acts as a peer discovery
 */
public class PeerDBDiscovery implements PeerDiscovery {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(PeerDBDiscovery.class);

    /**
     * The design is based pretty heavily on sipa/Bitcoin Core's addrman/addr.dat:
     *  * Addresses are stored in limited-size sets and thrown away randomly with weight given to addresses not seen in
     *    some time (ie no peers have announced them in some time and we have note successfully connected to them in some
     *    time). Unlike Bitcoin Core's addrman, we do not have separate groups of sets for addresses which are new and
     *    addresses which have been connected to in the past.
     *  * Sets are indexed by three values: first the IP subnet of the peer which announced the given address, second by
     *    the address' IP subnet, and third by a secret key which randomizes where collisions will happen. The random
     *    key and announcing peer subnet is used to select a group of 16 sets. The random key and IP's subnet are then
     *    used to select one of these 16 sets, to which the address is added.
     */
    static final int SETS_PER_SOURCE = 16;
    static final int TOTAL_SETS = 256;
    static final int MAX_SET_SIZE = 128;
    static final int ADDRESSES_RETURNED = 4096; // Way more than DNSSeeds will return, so that we can maybe hide them
    static final int MAX_ADDRESSES_FACTOR = 8; // Only ever return at max 1/8th the total addresses we have

    protected class PeerData {
        public PeerAddress address;
        public volatile long vTimeLastHeard = Utils.now().getTime(); // Last time we heard of this node (ie a peer told us about it/we connected to it)
        public volatile long lastConnected = 0; // Last time we successfully connected to this node
        public long triedSinceLastConnection = 0; // Number of times we've tried to connect to this node since the last success

        PeerData(PeerAddress address) { this.address = address; }

        PeerData(InputStream input) throws IOException {
            byte[] peerAddress = new byte[30 + 8*3];
            checkState(input.read(peerAddress) == peerAddress.length);
            address = new PeerAddress(params, peerAddress, 0, NetworkParameters.PROTOCOL_VERSION);
            vTimeLastHeard = Utils.readInt64(peerAddress, 30);
            lastConnected = Utils.readInt64(peerAddress, 30 + 8);
            triedSinceLastConnection = Utils.readInt64(peerAddress, 30 + 16);
        }

        synchronized void write(OutputStream s) throws IOException {
            address.bitcoinSerialize(s);
            Utils.int64ToByteStreamLE(vTimeLastHeard, s);
            Utils.int64ToByteStreamLE(lastConnected, s);
            Utils.int64ToByteStreamLE(triedSinceLastConnection, s);
            triedSinceLastConnection = Math.max(0, triedSinceLastConnection);
        }

        synchronized void connected() {
            triedSinceLastConnection = -1;
            lastConnected = Utils.now().getTime();
        }

        synchronized void disconnected() {
            triedSinceLastConnection++;
        }

        @Override public int hashCode() { return (int) (address.toSocketAddress().hashCode() ^ rotatingRandomKey); }
        @Override public boolean equals(Object o) { return (o instanceof PeerData) && ((PeerData) o).address.toSocketAddress().equals(address.toSocketAddress()); }
    }

    @VisibleForTesting class AddressSet extends HashSet<PeerData> {
        @Override
        public boolean add(PeerData peer) {
            if (size() >= MAX_SET_SIZE) {
                // Loop through our elements, throwing away ones which are considered useless
                Iterator<PeerData> it = iterator();
                while (it.hasNext()) {
                    if (!peerGood(it.next()))
                        it.remove();
                }
                if (size() >= MAX_SET_SIZE) {
                    // If we're still too large, throw away an element selected based on rotatingRandomKey
                    it = iterator();
                    it.next(); it.remove();
                }
            }
            return super.add(peer);
        }
    }

    private NetworkParameters params;

    @VisibleForTesting List<AddressSet> addressBuckets = new ArrayList<AddressSet>(TOTAL_SETS);
    @VisibleForTesting Map<InetAddress, PeerData> addressToSetMap = new HashMap<InetAddress, PeerData>(); // We never keep multiple entries for a peer on different ports
    // Keep a static random key that is used to select set groups/sets and a rotating random key that changes on each restart
    private long randomKey, rotatingRandomKey = new Random(Utils.now().getTime()).nextLong();

    File db;

    private void writeAddressGroup(PeerAddress address, OutputStream out) throws IOException {
        // We use a system similar to GetGroup() in Bitcoin Core, however we do not handle nearly as many cases for
        // address types which are rarely used (RFC6052) and a few which are used more commonly (Teredo, 6to4).
        // While more should probably be added, not having them simply means we consider entire blocks a single group
        // instead of splitting them into more realistic groups.
        byte[] addressBytes = address.getAddr().getAddress();
        if (address.getAddr() instanceof Inet4Address) {
            // If the address is in a /8 that was allocated to a single group, use the /8, otherwise use the /16
            if (addressBytes[0] <= 57 && addressBytes[0] != 50 && addressBytes[0] != 49 && addressBytes[0] != 46 &&
                    addressBytes[0] != 42 && addressBytes[0] != 41 && addressBytes[0] != 39 && addressBytes[0] != 37 &&
                    addressBytes[0] != 36 && addressBytes[0] != 31 && addressBytes[0] != 27 && addressBytes[0] != 24 &&
                    addressBytes[0] != 23 && addressBytes[0] != 14 && addressBytes[0] != 5 && addressBytes[0] != 2 &&
                    addressBytes[0] != 1)
                out.write(addressBytes[0]);
            else
                out.write(Arrays.copyOf(addressBytes, 2));
        } else {
            // If the address is a Tor-encapsulated IPv6, use the whole /48 (ie all tor addresses are the same group, for now)
            if (addressBytes[0] == 0xfd && addressBytes[1] == 0x87 && addressBytes[2] == 0xdb &&
                    addressBytes[3] == 0x7e && addressBytes[4] == 0xeb && addressBytes[5] == 0x43)
                out.write(Arrays.copyOf(addressBytes, 6));
            // If the address is HE (tunnelbroker.net), use the /40 (they allocate up to /48s)
            else if (addressBytes[0] == 20 && addressBytes[1] == 1 && addressBytes[2] == 4 && addressBytes[3] == 70)
                out.write(Arrays.copyOf(addressBytes, 40/8));
            else // otherwise just use the /32
                out.write(Arrays.copyOf(addressBytes, 32/8));
        }
    }

    // May return null if address.getAddr() != from.getAddr(), otherwise must return a PeerData
    private synchronized PeerData addAddress(PeerAddress address, PeerAddress from) {
        PeerData peer = addressToSetMap.get(address.getAddr());
        if (peer == null) {
            peer = new PeerData(address);
            addressToSetMap.put(address.getAddr(), peer);

            try {
                // setSelector is used to select the set used within the possible sets for a given source group
                // it is used % SETS_PER_SOURCE as there should only be SETS_PER_SOURCE sets used per source group
                ByteArrayOutputStream setWithinGroupSelector = new UnsafeByteArrayOutputStream();
                Utils.uint32ToByteStreamLE(randomKey, setWithinGroupSelector);
                writeAddressGroup(address, setWithinGroupSelector);

                ByteArrayOutputStream setSelector = new UnsafeByteArrayOutputStream();
                Utils.uint32ToByteStreamLE(randomKey, setSelector);
                writeAddressGroup(from, setSelector); // Select which group of sets we will use
                // Now select one of SETS_PER_SOURCE sets to use within the selected group
                Utils.uint32ToByteStreamLE(Math.abs(Sha256Hash.create(setWithinGroupSelector.toByteArray()).hashCode()) % SETS_PER_SOURCE, setSelector);

                addressBuckets.get(Math.abs(Sha256Hash.create(setSelector.toByteArray()).hashCode()) % TOTAL_SETS).add(peer);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            // We only keep one entry per IP, so if the port differs we have to either throw peer away or replace it
            if (address.getPort() != peer.address.getPort()) {
                if (from.getAddr().equals(address.getAddr())) // If the node announced itself or we connected, replace
                    peer.address = address;
                else // Otherwise just ignore the new address (the old one will get thrown out eventually if necessary)
                    return null;
            }
            // Pick up new service bits
            peer.address.setServices(peer.address.getServices().or(address.getServices()));
        }
        peer.vTimeLastHeard = Utils.now().getTime();
        return peer;
    }

    /**
     * Creates a PeerDB for the given peergoup, adding this as a PeerDiscovery to the given group.
     */
    public PeerDBDiscovery(NetworkParameters params, File db, PeerGroup group) {
        this.params = params;
        this.db = db;
        for (int i = 0; i < TOTAL_SETS; i++)
            addressBuckets.add(new AddressSet());

        boolean doInit = !db.exists();
        if (!doInit)
            doInit = !loadFromFile(db);
        if (doInit)
            randomKey = new Random(Utils.now().getTime()).nextLong();

        group.addEventListener(new AbstractPeerEventListener() {
            @Override
            public Message onPreMessageReceived(Peer p, Message m) {
                if (m instanceof AddressMessage) {
                    for (PeerAddress address : ((AddressMessage) m).getAddresses())
                        addAddress(address, p.getAddress());
                }
                return m;
            }

            @Override
            public void onPeerConnected(Peer p, int peerCount) {
                // When PeerGroups accept incoming connections, we should skip this and onPeerDisconnected
                addAddress(p.getAddress(), p.getAddress()).connected();
            }
            
            @Override
            public void onPeerDisconnected(Peer p, int peerCount) {
                addAddress(p.getAddress(), p.getAddress()).disconnected();
            }
        });
        group.addPeerDiscovery(this);
    }

    @Override
    public InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        int addressesToReturn = Math.min(ADDRESSES_RETURNED, addressToSetMap.size()/MAX_ADDRESSES_FACTOR);
        InetSocketAddress[] addresses = new InetSocketAddress[addressesToReturn];
        //TODO: There is a better way to get a random set here
        ArrayList<PeerData> peerList = new ArrayList<PeerData>(addressToSetMap.values());
        Collections.shuffle(peerList);
        Iterator<PeerData> iterator = peerList.iterator();
        for (int i = 0; i < addressesToReturn; i++) {
            PeerData peer = iterator.next();
            while (!peerGood(peer) && iterator.hasNext())
                peer = iterator.next();
            if (iterator.hasNext())
                addresses[i] = peer.address.toSocketAddress();
        }
        return addresses;
    }

    protected boolean peerGood(PeerData peerData) {
        return (peerData.lastConnected != 0 || peerData.triedSinceLastConnection < 3) && // Tried 3 times and never connected
                (peerData.lastConnected > Utils.now().getTime() - TimeUnit.DAYS.toSeconds(5) ||
                        peerData.triedSinceLastConnection < 5) && // Tried 5 times since last connection, which was > 5 days ago
                (peerData.vTimeLastHeard > Utils.now().getTime() - TimeUnit.DAYS.toSeconds(14)); // Haven't heard of node in 14 days
    }

    @Override public void shutdown() {
        try {
            saveToFile(db);
        } catch (IOException e) {
            log.error("Failed to save Peer set to file", e);
        }
    }

    private boolean loadFromFile(File f) {
        try {
            InputStream s = new FileInputStream(f);
            byte[] randomKeyBytes = new byte[8];
            if (s.read(randomKeyBytes) != randomKeyBytes.length)
                return false;
            randomKey = Utils.readInt64(randomKeyBytes, 0);
            for (int i = 0; i < TOTAL_SETS; i++) {
                byte[] addressCountBytes = new byte[4];
                checkState(s.read(addressCountBytes) == addressCountBytes.length);
                int addresses = (int) Utils.readUint32(addressCountBytes, 0);
                checkState(addresses <= MAX_SET_SIZE);
                for (int j = 0; j < addresses; j++) {
                    PeerData peer = new PeerData(s);
                    addressBuckets.get(i).add(peer);
                    addressToSetMap.put(peer.address.getAddr(), peer);
                }
            }
            return true;
        } catch (FileNotFoundException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    //TODO Call on a regular basis
    private synchronized void saveToFile(File f) throws IOException {
        OutputStream s = new FileOutputStream(f);
        Utils.int64ToByteStreamLE(randomKey, s);
        for (int i = 0; i < TOTAL_SETS; i++) {
            Utils.uint32ToByteStreamLE(addressBuckets.get(i).size(), s);
            for (PeerData peerData : addressBuckets.get(i))
                peerData.write(s);
        }
    }
}
