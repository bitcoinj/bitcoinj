package com.google.bitcoin.core;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Parent class for header only message that don't have a payload
 * @author git
 *
 */
public abstract class EmptyMessage extends Message {

	public EmptyMessage() {
	}

	public EmptyMessage(NetworkParameters params) {
		super(params);
	}

	public EmptyMessage(NetworkParameters params, byte[] msg, int offset, int protocolVersion) throws ProtocolException {
		super(params, msg, offset, protocolVersion);
	}

	public EmptyMessage(NetworkParameters params, byte[] msg, int offset) throws ProtocolException {
		super(params, msg, offset);
	}

	@Override
	final void bitcoinSerializeToStream(OutputStream stream) throws IOException {
	}

}
