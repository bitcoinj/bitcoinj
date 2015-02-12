package com.subgraph.orchid.sockets;

import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.Threading;
import com.subgraph.orchid.TorClient;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;

public class OrchidSocketImpl extends SocketImpl {
	private final TorClient torClient;

	private Lock streamLock = Threading.lock("stream");
	private Stream stream;
	
	OrchidSocketImpl(TorClient torClient) {
		this.torClient = torClient;
		this.fd = new FileDescriptor();
	}

	public void setOption(int optID, Object value) throws SocketException {
		throw new UnsupportedOperationException();
	}

	public Object getOption(int optID) throws SocketException {
		if(optID == SocketOptions.SO_LINGER) {
			return 0;
		} else if(optID == SocketOptions.TCP_NODELAY) {
			return Boolean.TRUE;
		} else if(optID == SocketOptions.SO_TIMEOUT) {
			return 0;
		} else {
			return 0;
		}
	}

	@Override
	protected void create(boolean stream) throws IOException {
		
	}

	@Override
	protected void connect(String host, int port) throws IOException {
		SocketAddress endpoint =
				InetSocketAddress.createUnresolved(host, port);
		connect(endpoint, 0);
	}

	@Override
	protected void connect(InetAddress address, int port) throws IOException {
		SocketAddress endpoint =
				InetSocketAddress.createUnresolved(address.getHostAddress(), port);
		connect(endpoint, 0);
	}

	@Override
	protected void connect(SocketAddress address, int timeout)
			throws IOException {
		if(!(address instanceof InetSocketAddress)) {
			throw new IllegalArgumentException("Unsupported address type");
		}
		final InetSocketAddress inetAddress = (InetSocketAddress) address;
		
		doConnect(addressToName(inetAddress), inetAddress.getPort());
	}
	
	private String addressToName(InetSocketAddress address) {
		if(address.getAddress() != null) {
			return address.getAddress().getHostAddress();
		} else {
			return address.getHostName();
		}
	}

	private void doConnect(String host, int port) throws IOException {
		Stream stream;

		// Try to avoid holding the stream lock here whilst calling into torclient to avoid accidental inversions.

		streamLock.lock();
		stream = this.stream;
		streamLock.unlock();

		if (stream != null)
			throw new SocketException("Already connected");

		try {
			stream = torClient.openExitStreamTo(host, port);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new SocketException("connect() interrupted");
		} catch (TimeoutException e) {
			throw new SocketTimeoutException();
		} catch (OpenFailedException e) {
			throw new ConnectException(e.getMessage());
		}

		streamLock.lock();
		if (this.stream != null) {
			// Raced with another concurrent call.
			streamLock.unlock();
			stream.close();
		} else {
			this.stream = stream;
			streamLock.unlock();
		}
	}

	@Override
	protected void bind(InetAddress host, int port) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected void listen(int backlog) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected void accept(SocketImpl s) throws IOException {
		throw new UnsupportedOperationException();
	}

	private Stream getStream() throws IOException {
		streamLock.lock();
		try {
			if (stream == null)
				throw new IOException("Not connected");
			return stream;
		} finally {
			streamLock.unlock();
		}
	}

	@Override
	protected InputStream getInputStream() throws IOException {
		return getStream().getInputStream();
	}

	@Override
	protected OutputStream getOutputStream() throws IOException {
		return getStream().getOutputStream();
	}

	@Override
	protected int available() throws IOException {
		return getStream().getInputStream().available();
	}

	@Override
	protected void close() throws IOException {
		Stream toClose;
		streamLock.lock();
		toClose = this.stream;
		this.stream = null;
		streamLock.unlock();
		if (toClose != null)
			toClose.close();
	}

	@Override
	protected void sendUrgentData(int data) throws IOException {
		throw new UnsupportedOperationException();
	}
	
	 protected void shutdownInput() throws IOException {
	  //throw new IOException("Method not implemented!");
	}
	 
	 protected void shutdownOutput() throws IOException {
	  //throw new IOException("Method not implemented!");
	}
}
