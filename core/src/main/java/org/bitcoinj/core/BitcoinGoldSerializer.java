package org.bitcoinj.core;

public class BitcoinGoldSerializer extends BitcoinSerializer {
    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param params      networkParams used to create Messages instances and termining packetMagic
     * @param parseRetain retain the backing byte array of a message for fast reserialization.
     */
    public BitcoinGoldSerializer(NetworkParameters params, boolean parseRetain) {
        super(params, parseRetain);
    }

    @Override
    public Block makeBlock(final byte[] payloadBytes, final int offset, final int length) throws ProtocolException {
        return new Block(params, payloadBytes, offset, this, length);
    }
}
