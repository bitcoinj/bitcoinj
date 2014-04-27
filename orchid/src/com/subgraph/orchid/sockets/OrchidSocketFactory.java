package com.subgraph.orchid.sockets;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import javax.net.SocketFactory;

import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorClient;

public class OrchidSocketFactory extends SocketFactory {
	private final TorClient torClient;
	private final boolean exceptionOnLocalBind;
	
	public OrchidSocketFactory(TorClient torClient) {
		this(torClient, true);
	}

	public OrchidSocketFactory(TorClient torClient, boolean exceptionOnLocalBind) {
		this.torClient = torClient;
		this.exceptionOnLocalBind = exceptionOnLocalBind;
	}

    @Override
    public Socket createSocket() throws IOException {
        return createSocketInstance();
    }

    @Override
	public Socket createSocket(String host, int port) throws IOException,
			UnknownHostException {
        final Socket s = createSocketInstance();
        return connectOrchidSocket(s, host, port);
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost,
			int localPort) throws IOException, UnknownHostException {
		if(exceptionOnLocalBind) {
			throw new UnsupportedOperationException("Cannot bind to local address");
		}
		return createSocket(host, port);
	}

	@Override
	public Socket createSocket(InetAddress address, int port) throws IOException {
        final Socket s = createSocketInstance();
		return connectOrchidSocket(s, address.getHostAddress(), port);
	}

	@Override
	public Socket createSocket(InetAddress address, int port,
			InetAddress localAddress, int localPort) throws IOException {
		if(exceptionOnLocalBind) {
			throw new UnsupportedOperationException("Cannot bind to local address");
		}
		return createSocket(address, port);
	}

	private Socket connectOrchidSocket(Socket s, String host, int port) throws IOException {
		final SocketAddress endpoint = InetSocketAddress.createUnresolved(host, port);
		s.connect(endpoint);
		return s;
	}
	
	private Socket createSocketInstance() throws SocketException {
		final OrchidSocketImpl impl = new OrchidSocketImpl(torClient);
		if(Tor.isAndroidRuntime()) {
			return new AndroidSocket(impl);
		} else {
			// call protected constructor
			return new Socket(impl) {};
		}
	}
}
