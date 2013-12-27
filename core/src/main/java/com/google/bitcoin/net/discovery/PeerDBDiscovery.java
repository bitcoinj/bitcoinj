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
import net.jcip.annotations.GuardedBy;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A Peer discovery mechanism that keeps a database of peers which are announced by other peers and which we've
 * connected to and returns a subset of those.</p>
 *
 * <p>It is important to use a peer db in addition to DNS seeds (via a {@link DnsDiscovery}) as it:<ul>
 *     <li>Spreads load across the network better, instead of having all bitcoinj clients connect to a specific set of
 *     (rotating) peers.</li>
 *     <li>Prevents DNS seeds from (maliciously or accidentally) forcing you to connect to a specific set of nodes which
 *     are conspiring to provide bad data.</li>
 *     <li>Allows for future protocol changes which allow nodes to fully verify the chain without serving the entire
 *     blockchain.</li>
 * </ul></p>
 *
 * <p>The design is based pretty heavily on sipa/Bitcoin Core's addrman/addr.dat:
 * <ul>
 * <li>Addresses are stored in limited-size sets and thrown away randomly with weight given to addresses not seen in
 * some time (ie no peers have announced them in some time and we have not successfully connected to them in some time).
 * Unlike Bitcoin Core's addrman, we do not have separate groups of sets for addresses which are new and addresses which
 * have been connected to in the past.</li>
 * <li>Sets are indexed by three values: first the IP subnet of the peer which announced the given address, second by
 * the address' IP subnet, and third by a random key which randomizes where collisions will happen. The random key and
 * announcing peer subnet is used to select a group of 16 sets. The random key and IP's subnet are then used to select
 * one of these 16 sets, to which the address is added.</li>
 * <li>The random key is important as it prevents determinism and makes it impossible to predict which sets a given
 * source subnet is able to get its addresses placed in. Thus, an attacker which wants to fill the address database with
 * nodes it controls can only probabilistically fill all sets instead of being able to pick specific source IPs which
 * allow it to place entries in all sets.</li>
 * </ul></p>
 */
public class PeerDBDiscovery implements PeerDiscovery {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(PeerDBDiscovery.class);

    // Threading notes:
    //  * In general all calls will come in on the USER_THREAD so we're probably OK to just ignore threading, but we
    //    make some effort to ensure we are thread-safe against calls coming in via broken PeerGroup extensions.
    //  * This means addAddress is synchronized so PeerData objects are created and updated atomically, however
    //    PeerData.connected() is called outside of addAddress, so we have to ensure the fields it accesses are always
    //    accessed in a thread-safe manner.

    @VisibleForTesting static final int SETS_PER_SOURCE = 16;
    @VisibleForTesting static final int TOTAL_SETS = 256;
    static final int MAX_SET_SIZE = 128;
    private static final int ADDRESSES_RETURNED = 4096; // Way more than DNSSeeds will return, so that we can maybe hide them
    private static final int MAX_ADDRESSES_FACTOR = 8; // Only ever return at max 1/8th the total addresses we have

    @VisibleForTesting class PeerData {
        @VisibleForTesting PeerAddress address;
        @VisibleForTesting /*@GuardedBy("super")*/ volatile long vTimeLastHeard = Utils.currentTimeMillis(); // Last time we heard of this node (ie a peer told us about it/we connected to it)
        @VisibleForTesting @GuardedBy("this") long lastConnected = 0; // Last time we successfully connected to this node
        @VisibleForTesting @GuardedBy("this") long triedSinceLastConnection = 0; // Number of times we've tried to connect to this node since the last success

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
            lastConnected = Utils.currentTimeMillis();
        }

        synchronized void disconnected() {
            triedSinceLastConnection++;
        }

        synchronized boolean isBad() {
            return (lastConnected == 0 && triedSinceLastConnection >= 3) || // Tried 3 times and never connected
                    (lastConnected < Utils.currentTimeMillis() - TimeUnit.DAYS.toMillis(5) &&
                            triedSinceLastConnection >= 5) || // Tried 5 times since last connection, which was > 5 days ago
                    (vTimeLastHeard < Utils.currentTimeMillis() - TimeUnit.DAYS.toMillis(14)); // Haven't heard of node in 14 days
        }

        @Override public synchronized int hashCode() { return (int) (address.toSocketAddress().hashCode() ^ rotatingRandomKey); }
        @Override public synchronized boolean equals(Object o) { return (o instanceof PeerData) && ((PeerData) o).address.toSocketAddress().equals(address.toSocketAddress()); }
    }

    @VisibleForTesting class AddressSet extends HashSet<PeerData> {
        @Override
        public boolean add(PeerData peer) {
            if (size() == MAX_SET_SIZE) {
                // Loop through our elements, throwing away ones which are considered useless
                Iterator<PeerData> it = iterator();
                while (it.hasNext()) {
                    PeerData peerToCheck = it.next();
                    if (peerToCheck.isBad()) {
                        log.debug("Removing bad node " + peerToCheck.address);
                        it.remove();
                    }
                }
                if (size() == MAX_SET_SIZE) {
                    // If we're still too large, throw away an element selected based on rotatingRandomKey
                    it = iterator();
                    it.next(); it.remove();
                }
            }
            checkState(size() < MAX_SET_SIZE);
            return super.add(peer);
        }
    }

    private NetworkParameters params;

    @VisibleForTesting @GuardedBy("this") List<AddressSet> addressBuckets = new ArrayList<AddressSet>(TOTAL_SETS);
    // We never keep multiple entries for a peer on different ports as one of our primary goals it to get as diverse a set of peers as possible
    @VisibleForTesting @GuardedBy("this") Map<InetAddress, PeerData> addressToSetMap = new HashMap<InetAddress, PeerData>();
    // Keep a static random key that is used to select set groups/sets and a rotating random key that changes on each restart
    private long randomKey;
    private long rotatingRandomKey = new Random(Utils.currentTimeMillis()).nextLong();

    private final File db;

    // Write some data representing the subnet address is in to out. Trying to figure out which subnet size we should
    // use to ensure a single ISP/user cannot get in tons of address groups simply by switching IPs within their
    // allocation.
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
                // We write out information needed and use a cryptographic hash to ensure there are no sets of IP groups
                // which have a higher probability of filling all sets than any other sets of groups (and because we do
                // not use a secure random value for randomKey).
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
                throw new RuntimeException(e);
            }
        } else {
            // We only keep one entry per IP to ensure our set of peers is as diverse as possible, so if the port
            // differs we have to either throw peer away or replace it
            if (address.getPort() != peer.address.getPort()) {
                if (from.getAddr().equals(address.getAddr())) // If the node announced itself or we connected, replace
                    peer.address = address;
                else // Otherwise just ignore the new address (the old one will get thrown out eventually if necessary)
                    return null;
            }
            // Pick up new service bits
            peer.address.setServices(peer.address.getServices().or(address.getServices()));
        }
        peer.vTimeLastHeard = Utils.currentTimeMillis();
        return peer;
    }

    /**
     * Creates a PeerDB for the given {@link PeerGroup}, adding this as a PeerDiscovery to the given group.
     */
    public PeerDBDiscovery(NetworkParameters params, File db, PeerGroup group) {
        this.params = params;
        this.db = db;
        for (int i = 0; i < TOTAL_SETS; i++)
            addressBuckets.add(new AddressSet());

        boolean doInit = !db.exists();
        if (!doInit)
            doInit = !maybeLoadFromFile(db);
        if (doInit)
            randomKey = new Random(Utils.currentTimeMillis()).nextLong();

        listenForPeers(group);
        group.addPeerDiscovery(this);
    }

    /**
     * Attaches a {@link PeerEventListener} to the given {@link PeerGroup} which listens for {@link AddressMessage}
     * announcements and peer connections to track known peers.
     */
    public void listenForPeers(PeerGroup group) {
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
    }

    @Override
    public synchronized InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        int addressesToReturn = Math.min(ADDRESSES_RETURNED, addressToSetMap.size()/MAX_ADDRESSES_FACTOR);
        InetSocketAddress[] addresses = new InetSocketAddress[addressesToReturn];
        //TODO: There is a better way to get a random set here
        ArrayList<PeerData> peerList = new ArrayList<PeerData>(addressToSetMap.values());
        Collections.shuffle(peerList);
        Iterator<PeerData> iterator = peerList.iterator();
        for (int i = 0; i < addressesToReturn; i++) {
            PeerData peer = iterator.next();
            while (peer.isBad() && iterator.hasNext())
                peer = iterator.next();
            if (iterator.hasNext())
                addresses[i] = peer.address.toSocketAddress();
        }
        return addresses;
    }

    @Override public void shutdown() {
        try {
            saveToFile(db);
        } catch (IOException e) {
            log.error("Failed to save Peer set to file", e);
        }
    }

    @GuardedBy("this")
    private boolean maybeLoadFromFile(File f) {
        try {
            InputStream s = new FileInputStream(f);
            byte[] versionAndRandomKeyBytes = new byte[12];
            if (s.read(versionAndRandomKeyBytes) != versionAndRandomKeyBytes.length)
                return false;
            if (Utils.readUint32(versionAndRandomKeyBytes, 0) != 1)
                return false; // Newer version
            randomKey = Utils.readInt64(versionAndRandomKeyBytes, 4);
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
            log.error("Error reading PeerDB from file", e);
            return false;
        }
    }

    //TODO Call on a regular basis
    private synchronized void saveToFile(File f) throws IOException {
        OutputStream s = new FileOutputStream(f);
        Utils.uint32ToByteStreamLE(1, s); // Version tag
        Utils.int64ToByteStreamLE(randomKey, s);
        for (int i = 0; i < TOTAL_SETS; i++) {
            Utils.uint32ToByteStreamLE(addressBuckets.get(i).size(), s);
            for (PeerData peerData : addressBuckets.get(i))
                peerData.write(s);
        }
    }
}
