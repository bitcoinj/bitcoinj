/*
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.core.listeners;

import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.VerificationException;

import java.util.List;

/**
 * Listener interface for when the best chain has changed.
 */
public interface ReorganizeListener {

    /**
     * Called by the {@link BlockChain} when the best chain
     * (representing total work done) has changed. In this case,
     * we need to go through our transactions and find out if any have become invalid. It's possible for our balance
     * to go down in this case: money we thought we had can suddenly vanish if the rest of the network agrees it
     * should be so.<p>
     *
     * The oldBlocks/newBlocks lists are ordered height-wise from top first to bottom last (i.e. newest blocks first).
     */
    void reorganize(StoredBlock splitPoint, List<StoredBlock> oldBlocks,
                    List<StoredBlock> newBlocks) throws VerificationException;
}
