package com.subgraph.orchid.sockets;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketImpl;
import java.net.SocketOptions;
import java.net.SocketTimeoutException;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.TorClient;

public class OrchidSocketImpl extends SocketImpl {
	
	private final TorClient torClient;
	private final Object streamLock = new Object();	

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
		throw new UnsupportedOperationException();
	}

	@Override
	protected void connect(InetAddress address, int port) throws IOException {
		throw new UnsupportedOperationException();
		
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
		synchronized(streamLock) {
			if(stream != null) {
				throw new SocketException("Already connected");
			}
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

	@Override
	protected InputStream getInputStream() throws IOException {
		synchronized (streamLock) {
			if(stream == null) {
				throw new IOException("Not connected");
			}
			return stream.getInputStream();
		}
	}

	@Override
	protected OutputStream getOutputStream() throws IOException {
		synchronized (streamLock) {
			if(stream == null) {
				throw new IOException("Not connected");
			}
			return stream.getOutputStream();
		}
	}

	@Override
	protected int available() throws IOException {
		synchronized(streamLock) {
			if(stream == null) {
				throw new IOException("Not connected");
			}
			return stream.getInputStream().available();
		}
	}

	@Override
	protected void close() throws IOException {
		synchronized (streamLock) {
			if(stream != null) {
				stream.close();
				stream = null;
			}
		}
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
