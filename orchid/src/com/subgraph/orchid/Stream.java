package com.subgraph.orchid;

import java.io.InputStream;
import java.io.OutputStream;

public interface Stream {
	/**
	 * Returns the {@link Circuit} this stream belongs to.
	 * 
	 * @return The {@link Circuit} this stream belongs to.
	 */
	Circuit getCircuit();

	/**
	 * Returns the stream id value of this stream.
	 * 
	 * @return The stream id value of this stream.
	 */
	int getStreamId();

	
	CircuitNode getTargetNode();

	/**
	 * Close this stream.
	 */
	void close();

	/**
	 * Returns an {@link InputStream} for sending data on this stream.
	 * 
	 * @return An {@link InputStream} for transferring data on this stream.
	 */
	InputStream getInputStream();

	/**
	 * Returns an {@link OutputStream} for receiving data from this stream.
	 * 
	 * @return An {@link OutputStream} for receiving data from this stream.
	 */
	OutputStream getOutputStream();
	
	/**
	 * If the circuit and stream level packaging windows are open for this stream
	 * this method returns immediately, otherwise it blocks until both windows are
	 * open or the stream is closed.
	 */
	void waitForSendWindow();
}
