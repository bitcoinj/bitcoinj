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

import java.math.BigInteger;

// TODO: Make this be an interface with a convenience abstract impl.

/**
 * Implementing a subclass WalletEventListener allows you to learn when the contents of the wallet changes due to
 * receiving money or a block chain re-organize. Methods are called with the event listener object locked so your
 * implementation does not have to be thread safe. The default method implementations do nothing.
 */
public interface PeerEventListener {
    /**
     * This is called on a Peer thread when a block is received.
     *
     * @param peer The peer receiving the block
     * @param blocksLeft The number of blocks left to download
     */
    public void onBlocksDownloaded(Peer peer, int blocksLeft);
}
