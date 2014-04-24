package com.subgraph.orchid.sockets.sslengine;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class SSLEngineOutputStream extends OutputStream {

	private final SSLEngineManager manager;
	private final ByteBuffer outputBuffer;
	
	public SSLEngineOutputStream(SSLEngineManager manager) {
		this.manager = manager;
		this.outputBuffer = manager.getSendBuffer();
	}
	
	@Override
	public void write(int b) throws IOException {
		outputBuffer.put((byte) b);
		manager.write();
	}
	
	@Override
    public void write(byte b[], int off, int len) throws IOException {
		int written = 0;
		
		while(written < len) {
			int n = doWrite(b, off + written, len - written);
			
			written += n;
		}
    }
	
	@Override
	public void close() throws IOException {
		manager.close();
	}
	
	private int doWrite(byte[] b, int off, int len) throws IOException {
		int putLength = Math.min(len, outputBuffer.remaining());
		outputBuffer.put(b, off, putLength);
		manager.write();
		return putLength;
	}

}
