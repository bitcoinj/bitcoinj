/*
 * Copyright 2015 Ross Nicoll.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.utils;

import java.util.Stack;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

/**
 * Caching counter for the block versions within a moving window. This class
 * is NOT thread safe (as if two threads are trying to use it concurrently,
 * there's risk of getting versions out of sequence).
 *
 * @see org.bitcoinj.core.NetworkParameters#getMajorityWindow()
 * @see org.bitcoinj.core.NetworkParameters#getMajorityEnforceBlockUpgrade()
 * @see org.bitcoinj.core.NetworkParameters#getMajorityRejectBlockOutdated()
 */
public class VersionTally {
    /**
     * Cache of version numbers.
     */
    private final long[] versionWindow;

    /**
     * Offset within the version window at which the next version will be
     * written.
     */
    private int versionWriteHead = 0;

    /**
     * Number of versions written into the tally. Until this matches the length
     * of the version window, we do not have sufficient data to return values.
     */
    private int versionsStored = 0;

    public VersionTally(final NetworkParameters params) {
        versionWindow = new long[params.getMajorityWindow()];
    }

    /**
     * Add a new block version to the tally, and return the count for that version
     * within the window.
     *
     * @param version the block version to add.
     */
    public void add(final long version) {
        versionWindow[versionWriteHead++] = version;
        if (versionWriteHead == versionWindow.length) {
            versionWriteHead = 0;
        }
        versionsStored++;
    }

    /**
     * Get the count of blocks at or above the given version, within the window.
     *
     * @param version the block version to query.
     * @return the count for the block version, or null if the window is not yet
     * full.
     */
    public Integer getCountAtOrAbove(final long version) {
        if (versionsStored < versionWindow.length) {
            return null;
        }
        int count = 0;
        for (long l : versionWindow) {
            if (l >= version) {
                count++;
            }
        }

        return count;
    }

    /**
     * Initialize the version tally from the block store. Note this does not
     * search backwards past the start of the block store, so if starting from
     * a checkpoint this may not fill the window.
     *
     * @param blockStore block store to load blocks from.
     * @param chainHead current chain tip.
     */
    public void initialize(final BlockStore blockStore, final StoredBlock chainHead)
        throws BlockStoreException {
        StoredBlock versionBlock = chainHead;
        final Stack<Long> versions = new Stack<>();

        // We don't know how many blocks back we can go, so load what we can first
        versions.push(versionBlock.getHeader().getVersion());
        for (int headOffset = 0; headOffset < versionWindow.length; headOffset++) {
            versionBlock = versionBlock.getPrev(blockStore);
            if (null == versionBlock) {
                break;
            }
            versions.push(versionBlock.getHeader().getVersion());
        }

        // Replay the versions into the tally
        while (!versions.isEmpty()) {
            add(versions.pop());
        }
    }

    /**
     * Get the size of the version window.
     */
    public int size() {
        return versionWindow.length;
    }
}
