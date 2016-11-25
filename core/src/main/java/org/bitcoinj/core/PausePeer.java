package org.bitcoinj.core;

import javax.annotation.Nullable;

public class PausePeer extends Peer {

    public PausePeer(NetworkParameters params, VersionMessage ver, @Nullable AbstractBlockChain chain, PeerAddress remoteAddress) {
        super(params, ver, chain, remoteAddress);
    }

    public PausePeer(NetworkParameters params, VersionMessage ver, PeerAddress remoteAddress, @Nullable AbstractBlockChain chain) {
        super(params, ver, remoteAddress, chain);
    }

    public PausePeer(NetworkParameters params, VersionMessage ver, PeerAddress remoteAddress, @Nullable AbstractBlockChain chain, int downloadTxDependencyDepth) {
        super(params, ver, remoteAddress, chain, downloadTxDependencyDepth);
    }

    public PausePeer(NetworkParameters params, AbstractBlockChain blockChain, PeerAddress peerAddress, String thisSoftwareName, String thisSoftwareVersion) {
        super(params, blockChain, peerAddress, thisSoftwareName, thisSoftwareVersion);
    }

    /*
     * Pause blockchain download
     */
    public static void pauseDownload(Peer peer) {
        peer.setDownloadData(false);
    }

    /*
     * Clear block state and continue blockchain download
     */
    public static void continueDownload(Peer peer) {
        peer.pendingBlockDownloads.clear();
        peer.startBlockChainDownload();

    }
}
