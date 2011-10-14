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

/**
 * Implementing a PeerEventListener allows you to learn when significant Peer communication
 * has occurred.
 *
 * <p>Methods are called with the event listener object locked so your
 * implementation does not have to be thread safe.
 *
 * @author miron@google.com (Miron Cuperman a.k.a devrandom)
 */
public interface PeerEventListener {
    /**
     * Called on a Peer thread when a block is received.
     * <p/>
     * <p>The block may have transactions or may be a header only once getheaders is implemented.
     *
     * @param peer       the peer receiving the block
     * @param block      the downloaded block
     * @param blocksLeft the number of blocks left to download
     */
    public void onBlocksDownloaded(Peer peer, Block block, int blocksLeft);

    /**
     * Called when a download is started with the initial number of blocks to be downloaded.
     *
     * @param peer       the peer receiving the block
     * @param blocksLeft the number of blocks left to download
     */
    public void onChainDownloadStarted(Peer peer, int blocksLeft);

    /**
     * Called when a peer is connected
     *
     * @param peer
     * @param peerCount the total number of connected peers
     */
    public void onPeerConnected(Peer peer, int peerCount);

    /**
     * Called when a peer is disconnected
     *
     * @param peer
     * @param peerCount the total number of connected peers
     */
    public void onPeerDisconnected(Peer peer, int peerCount);
}
