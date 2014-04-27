package com.subgraph.orchid.circuits;

import java.io.IOException;
import java.io.OutputStream;

import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;

public class TorOutputStream extends OutputStream {

	private final StreamImpl stream;
	private RelayCell currentOutputCell;
	private volatile boolean isClosed;
	private long bytesSent;

	TorOutputStream(StreamImpl stream) {
		this.stream = stream;
		this.bytesSent = 0;
	}

	private void flushCurrentOutputCell() {
		if(currentOutputCell != null && currentOutputCell.cellBytesConsumed() > RelayCell.HEADER_SIZE) {
			stream.waitForSendWindowAndDecrement();
			stream.getCircuit().sendRelayCell(currentOutputCell);
			bytesSent += (currentOutputCell.cellBytesConsumed() - RelayCell.HEADER_SIZE);
		}

		currentOutputCell = new RelayCellImpl(stream.getTargetNode(), stream.getCircuit().getCircuitId(),
				stream.getStreamId(), RelayCell.RELAY_DATA);
	}

	long getBytesSent() {
		return bytesSent;
	}

	@Override
	public synchronized void write(int b) throws IOException {
		checkOpen();
		if(currentOutputCell == null || currentOutputCell.cellBytesRemaining() == 0)
			flushCurrentOutputCell();
		currentOutputCell.putByte(b);		
	}

	public synchronized void write(byte[] data, int offset, int length) throws IOException {
		checkOpen();
		if(currentOutputCell == null || currentOutputCell.cellBytesRemaining() == 0)
			flushCurrentOutputCell();

		while(length > 0) {
			if(length < currentOutputCell.cellBytesRemaining()) {
				currentOutputCell.putByteArray(data, offset, length);
				return;
			}
			final int writeCount = currentOutputCell.cellBytesRemaining();
			currentOutputCell.putByteArray(data, offset, writeCount);
			flushCurrentOutputCell();
			offset += writeCount;
			length -= writeCount;
		}
	}

	private void checkOpen() throws IOException {
		if(isClosed)
			throw new IOException("Output stream is closed");
	}

	public synchronized void flush() {
		if(isClosed)
			return;
		flushCurrentOutputCell();
	}

	public synchronized void close() {
		if(isClosed)
			return;
		flush();
		isClosed = true;
		currentOutputCell = null;
		stream.close();
	}

	public String toString() {
		return "TorOutputStream stream="+ stream.getStreamId() +" node="+ stream.getTargetNode();
	}
}
