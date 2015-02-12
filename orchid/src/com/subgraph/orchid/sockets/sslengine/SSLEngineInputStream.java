package com.subgraph.orchid.sockets.sslengine;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class SSLEngineInputStream extends InputStream {

	private final SSLEngineManager manager;
	private final ByteBuffer recvBuffer;
	private boolean isEOF;
	
	SSLEngineInputStream(SSLEngineManager manager) {
		this.manager = manager;
		this.recvBuffer = manager.getRecvBuffer();
	}
	
	@Override
	public int read() throws IOException {
		if(!fillRecvBufferIfEmpty()) {
			return -1;
		}
		final int b = recvBuffer.get() & 0xFF;
		recvBuffer.compact();
		return b;
	}
	
	@Override
    public int read(byte b[], int off, int len) throws IOException {
		if(!fillRecvBufferIfEmpty()) {
			return -1;
		}
		final int copyLen = Math.min(recvBuffer.remaining(), len);
		recvBuffer.get(b, off, copyLen);
		recvBuffer.compact();
		return copyLen;
    }

	@Override
	public void close() throws IOException {
		manager.close();
	}

	private boolean fillRecvBufferIfEmpty() throws IOException {
		if(isEOF) {
			return false;
		}
		if(recvBuffer.position() == 0) {
			if(manager.read() < 0) {
				isEOF = true;
				return false;
			}
		}
		recvBuffer.flip();
		return recvBuffer.hasRemaining();
	}
}
