package com.google.bitcoin.core;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Parent class for header only messages that don't have a payload.
 * Currently this includes getaddr, ping, verack as well as the special bitcoinj class UnknownMessage
 * @author git
 *
 */
public abstract class EmptyMessage extends Message {

	public EmptyMessage() {
	}

	public EmptyMessage(NetworkParameters params) {
		super(params);
	}

	public EmptyMessage(NetworkParameters params, byte[] msg, int offset) throws ProtocolException {
		super(params, msg, offset);
	}

	@Override
	final protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
	}

}
