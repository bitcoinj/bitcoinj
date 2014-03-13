package com.subgraph.orchid.circuits;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.Queue;

import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;
import com.subgraph.orchid.misc.GuardedBy;
import com.subgraph.orchid.misc.ThreadSafe;

@ThreadSafe
public class TorInputStream extends InputStream {

	private final static RelayCell CLOSE_SENTINEL = new RelayCellImpl(null, 0, 0, 0);
	private final static ByteBuffer EMPTY_BUFFER  = ByteBuffer.allocate(0);
	
	private final Stream stream;
	
	private final Object lock = new Object();
	
	/** Queue of RelayCells that have been received on this stream */
	@GuardedBy("lock") private final Queue<RelayCell> incomingCells;
	
	/** Number of unread data bytes in current buffer and in RELAY_DATA cells on queue */
	@GuardedBy("lock") private int availableBytes;
	
	/** Total number of data bytes received in RELAY_DATA cells on this stream */
	@GuardedBy("lock") private long bytesReceived;
	
	/** Bytes of data from the RELAY_DATA cell currently being consumed */
	@GuardedBy("lock") private ByteBuffer currentBuffer;
	
	/** Set when a RELAY_END cell is received */
	@GuardedBy("lock") private boolean isEOF;
	
	/** Set when close() is called on this stream */
	@GuardedBy("lock") private boolean isClosed;
	
	TorInputStream(Stream stream) {
		this.stream = stream;
		this.incomingCells = new LinkedList<RelayCell>();
		this.currentBuffer = EMPTY_BUFFER;
	}

	long getBytesReceived() {
		synchronized (lock) {
			return bytesReceived;
		}
	}

	@Override
	public int read() throws IOException {
		synchronized (lock) {
			if(isClosed) {
				throw new IOException("Stream closed");
			}
			refillBufferIfNeeded();
			if(isEOF) {
				return -1;
			}
			availableBytes -= 1;
			return currentBuffer.get() & 0xFF;
		}
	}

	
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	public synchronized int read(byte[] b, int off, int len) throws IOException {
		synchronized (lock) {
			if(isClosed) {
				throw new IOException("Stream closed");
			}

			checkReadArguments(b, off, len);

			if(len == 0) {
				return 0;
			}
			
			refillBufferIfNeeded();
			if(isEOF) {
				return -1;
			}
			
			int bytesRead = 0;
			int bytesRemaining = len;
			
			while(bytesRemaining > 0 && !isEOF) {
				refillBufferIfNeeded();
				bytesRead += readFromCurrentBuffer(b, off + bytesRead, len - bytesRead);
				bytesRemaining = len - bytesRead;
				if(availableBytes == 0) {
					return bytesRead;
				}
			}
			return bytesRead;
		}
	}
	
	@GuardedBy("lock")
	private int readFromCurrentBuffer(byte[] b, int off, int len) {
		final int readLength = (currentBuffer.remaining() >= len) ? (len) : (currentBuffer.remaining());
		currentBuffer.get(b, off, readLength);
		availableBytes -= readLength;
		return readLength;
	}

	private void checkReadArguments(byte[] b, int off, int len) {
		if(b == null) {
			throw new NullPointerException();
		}
		if( (off < 0) || (off >= b.length) || (len < 0) ||
				((off + len) > b.length) || ((off + len) < 0)) {
			throw new IndexOutOfBoundsException();
		}
	}

	public int available() {
		synchronized(lock) {
			return availableBytes;
		}
	}

	public void close() {
		synchronized (lock) {
			if(isClosed) {
				return;
			}
			isClosed = true;
			
			incomingCells.add(CLOSE_SENTINEL);
			lock.notifyAll();
		}
		stream.close();
	}

	void addEndCell(RelayCell cell) {
		synchronized (lock) {
			if(isClosed) {
				return;
			}
			incomingCells.add(cell);
			lock.notifyAll();
		}
	}

	void addInputCell(RelayCell cell) {
		synchronized (lock) {
			if(isClosed) {
				return;
			}
			incomingCells.add(cell);
			bytesReceived += cell.cellBytesRemaining();
			availableBytes += cell.cellBytesRemaining();
			lock.notifyAll();
		}
	}

	@GuardedBy("lock")
	// When this method (or fillBuffer()) returns either isEOF is set or currentBuffer has at least one byte to read
	private void refillBufferIfNeeded() throws IOException {
		if(!isEOF) {
			if(currentBuffer.hasRemaining()) {
				return;
			}
			fillBuffer();
		}
	}

	@GuardedBy("lock")
	private void fillBuffer() throws IOException {
		while(true) {
			processIncomingCell(getNextCell());
			if(isEOF || currentBuffer.hasRemaining()) {
				return;
			}
		}
	}

	@GuardedBy("lock")
	private void processIncomingCell(RelayCell nextCell) throws IOException {
		if(isClosed || nextCell == CLOSE_SENTINEL) {
			throw new IOException("Input stream closed");
		}
		
		switch(nextCell.getRelayCommand()) {
		case RelayCell.RELAY_DATA:
			currentBuffer = nextCell.getPayloadBuffer();
			break;
		case RelayCell.RELAY_END:
			currentBuffer = EMPTY_BUFFER;
			isEOF = true;
			break;
		default:
			throw new IOException("Unexpected RelayCell command type in TorInputStream queue: "+ nextCell.getRelayCommand());
		}
	}
	
	@GuardedBy("lock")
	private RelayCell getNextCell() throws IOException {
		try {
			while(incomingCells.isEmpty()) {
				lock.wait();
			}
			return incomingCells.remove();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException("Read interrupted");
		}
	}
	
	int unflushedCellCount() {
		synchronized (lock) {
			return incomingCells.size();
		}
	}

	public String toString() {
			return "TorInputStream stream="+ stream.getStreamId() +" node="+ stream.getTargetNode();
	}
}
