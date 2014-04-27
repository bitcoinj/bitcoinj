package com.subgraph.orchid.sockets;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import com.subgraph.orchid.sockets.sslengine.SSLEngineSSLSocket;

public class AndroidSSLSocketFactory extends SSLSocketFactory {

	private final SSLContext sslContext;

	public AndroidSSLSocketFactory() throws NoSuchAlgorithmException {
		this(SSLContext.getDefault());
	}
	
	public AndroidSSLSocketFactory(SSLContext sslContext) {
		this.sslContext = sslContext;
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return sslContext.getDefaultSSLParameters().getCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return sslContext.getSupportedSSLParameters().getCipherSuites();
		
	}

	@Override
	public Socket createSocket(Socket s, String host, int port,
			boolean autoClose) throws IOException {

		return new SSLEngineSSLSocket(s, sslContext);
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException,
			UnknownHostException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost,
			int localPort) throws IOException, UnknownHostException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Socket createSocket(InetAddress address, int port,
			InetAddress localAddress, int localPort) throws IOException {
		throw new UnsupportedOperationException();
	}
}
