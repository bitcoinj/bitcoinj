package org.bitcoinj.core;

/**
 * <p>A new message, "sendheaders", which indicates that a node prefers to receive new block announcements
 * via a "headers" message rather than an "inv".</p>
 *
 * <p>See https://github.com/bitcoin/bips/blob/master/bip-0130.mediawiki</p>
 */
public class SendHeadersMessage extends EmptyMessage {
    public SendHeadersMessage() {
    }

    // this is needed by the BitcoinSerializer
    public SendHeadersMessage(NetworkParameters params, byte[] payload) {
    }
}