package com.google.bitcoin.core;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Parent class for header only messages that don't have a payload.
 * Currently this includes getaddr, ping, verack as well as the special bitcoinj class UnknownMessage
 *
 * @author git
 */
public abstract class EmptyMessage extends Message {
    private static final long serialVersionUID = 8240801253854151802L;

    public EmptyMessage() {
        length = 0;
    }

    public EmptyMessage(NetworkParameters params) {
        super(params);
        length = 0;
    }

    public EmptyMessage(NetworkParameters params, byte[] msg, int offset) throws ProtocolException {
        super(params, msg, offset);
        length = 0;
    }

    @Override
    final protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
    }

    @Override
    int getMessageSize() {
        return 0;
    }

    /* (non-Javadoc)
      * @see com.google.bitcoin.core.Message#parse()
      */
    @Override
    void parse() throws ProtocolException {
    }

    /* (non-Javadoc)
      * @see com.google.bitcoin.core.Message#parseLite()
      */
    @Override
    protected void parseLite() throws ProtocolException {
        length = 0;
    }

    /* (non-Javadoc)
      * @see com.google.bitcoin.core.Message#ensureParsed()
      */
    @Override
    public void ensureParsed() throws ProtocolException {
        parsed = true;
    }

    /* (non-Javadoc)
      * @see com.google.bitcoin.core.Message#bitcoinSerialize()
      */
    @Override
    public byte[] bitcoinSerialize() {
        return new byte[0];
    }


}
