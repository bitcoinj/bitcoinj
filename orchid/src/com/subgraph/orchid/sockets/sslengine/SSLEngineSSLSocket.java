package com.subgraph.orchid.sockets.sslengine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class SSLEngineSSLSocket extends SSLSocket implements HandshakeCallbackHandler {

	private final SSLEngine engine;
	private final SSLEngineManager manager;
	
	private Socket socket;
	private InputStream inputStream;
	private OutputStream outputStream;
	private final List<HandshakeCompletedListener> listenerList;
	public SSLEngineSSLSocket(Socket socket, SSLContext context) throws IOException {
		this.engine = createSSLEngine(context);
		this.socket = socket;
		this.manager = new SSLEngineManager(engine, this, socket.getInputStream(), socket.getOutputStream());
		this.listenerList = new CopyOnWriteArrayList<HandshakeCompletedListener>();
	}
	
	private static SSLEngine createSSLEngine(SSLContext context) {
		final SSLEngine engine = context.createSSLEngine();
		engine.setUseClientMode(true);
		return engine;
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return engine.getSupportedCipherSuites();
	}

	@Override
	public String[] getEnabledCipherSuites() {
		return engine.getEnabledCipherSuites();
	}

	@Override
	public void setEnabledCipherSuites(String[] suites) {
		engine.setEnabledCipherSuites(suites);
	}

	@Override
	public String[] getSupportedProtocols() {
		return engine.getSupportedProtocols();
	}

	@Override
	public String[] getEnabledProtocols() {
		return engine.getEnabledProtocols();
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		engine.setEnabledProtocols(protocols);
	}

	@Override
	public SSLSession getSession() {
		return engine.getSession();
	}

	@Override
	public void addHandshakeCompletedListener(
			HandshakeCompletedListener listener) {
		listenerList.add(listener);
	}

	@Override
	public void removeHandshakeCompletedListener(
			HandshakeCompletedListener listener) {
		listenerList.remove(listener);
	}

	@Override
	public void startHandshake() throws IOException {
		manager.startHandshake();
	}

	@Override
	public void setUseClientMode(boolean mode) {
		engine.setUseClientMode(mode);
	}

	@Override
	public boolean getUseClientMode() {
		return engine.getUseClientMode();
	}

	@Override
	public void setNeedClientAuth(boolean need) {
		engine.setNeedClientAuth(need);
	}

	@Override
	public boolean getNeedClientAuth() {
		return engine.getNeedClientAuth();
	}

	@Override
	public void setWantClientAuth(boolean want) {
		engine.setWantClientAuth(want);
	}

	@Override
	public boolean getWantClientAuth() {
		return engine.getWantClientAuth();
	}

	@Override
	public void connect(SocketAddress endpoint) throws IOException {
		throw new IOException("Socket is already connected");
	}

	@Override
	public void connect(SocketAddress endpoint, int timeout) throws IOException {
		throw new IOException("Socket is already connected");
	}

	@Override
	public void bind(SocketAddress bindpoint) throws IOException {
		throw new IOException("Socket is already connected");
	}

	@Override
	public InetAddress getInetAddress() {
		return socket.getInetAddress();
	}

	@Override
	public InetAddress getLocalAddress() {
		return socket.getLocalAddress();
	}

	@Override
	public int getPort() {
		return socket.getPort();
	}

	@Override
	public int getLocalPort() {
		return socket.getLocalPort();
	}

	@Override
	public SocketAddress getRemoteSocketAddress() {
		return socket.getRemoteSocketAddress();
	}

	@Override
	public SocketAddress getLocalSocketAddress() {
		return socket.getLocalSocketAddress();
	}

	@Override
	public void setTcpNoDelay(boolean on) throws SocketException {
		socket.setTcpNoDelay(on);
	}

	@Override
	public boolean getTcpNoDelay() throws SocketException {
		return socket.getTcpNoDelay();
	}

	@Override
	public void setSoLinger(boolean on, int linger) throws SocketException {
		socket.setSoLinger(on, linger);
	}

	@Override
	public int getSoLinger() throws SocketException {
		return socket.getSoLinger();
	}

	@Override
	public void setOOBInline(boolean on) throws SocketException {
		socket.setOOBInline(on);
	}

	@Override
	public boolean getOOBInline() throws SocketException {
		return socket.getOOBInline();
	}

	@Override
	public synchronized void setSoTimeout(int timeout) throws SocketException {
		socket.setSoTimeout(timeout);
	}

	@Override
	public synchronized int getSoTimeout() throws SocketException {
		return socket.getSoTimeout();
	}

	@Override
	public synchronized void setSendBufferSize(int size) throws SocketException {
		socket.setSendBufferSize(size);
	}

	@Override
	public synchronized int getSendBufferSize() throws SocketException {
		return socket.getSendBufferSize();
	}

	@Override
	public synchronized void setReceiveBufferSize(int size)
			throws SocketException {
		socket.setReceiveBufferSize(size);
	}

	@Override
	public synchronized int getReceiveBufferSize() throws SocketException {
		return socket.getReceiveBufferSize();
	}

	@Override
	public void setKeepAlive(boolean on) throws SocketException {
		socket.setKeepAlive(on);
	}

	@Override
	public boolean getKeepAlive() throws SocketException {
		return socket.getKeepAlive();
	}

	@Override
	public void setTrafficClass(int tc) throws SocketException {
		socket.setTrafficClass(tc);
	}

	@Override
	public int getTrafficClass() throws SocketException {
		return socket.getTrafficClass();
	}

	@Override
	public void setReuseAddress(boolean on) throws SocketException {
		socket.setReuseAddress(on);
	}

	@Override
	public boolean getReuseAddress() throws SocketException {
		return socket.getReuseAddress();
	}

	@Override
	public void shutdownInput() throws IOException {
		throw new UnsupportedOperationException("shutdownInput() not supported on SSL Sockets");
	}

	@Override
	public void shutdownOutput() throws IOException {
		throw new UnsupportedOperationException("shutdownOutput() not supported on SSL Sockets");
	}

	@Override
	public boolean isInputShutdown() {
		return socket.isInputShutdown();
	}

	@Override
	public boolean isOutputShutdown() {
		return socket.isOutputShutdown();
	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
		engine.setEnableSessionCreation(flag);
	}

	@Override
	public boolean getEnableSessionCreation() {
		return engine.getEnableSessionCreation();
	}

	@Override
	public synchronized InputStream getInputStream() throws IOException {
		if(inputStream == null) {
			inputStream = new SSLEngineInputStream(manager);
		}
		return inputStream;
	}

	@Override
	public OutputStream getOutputStream() throws IOException {
		if(outputStream == null) {
			outputStream = new SSLEngineOutputStream(manager);
		}
		return outputStream;
	}

	public void handshakeCompleted() {
		if(listenerList.isEmpty()) {
			return;
		}
		final HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, engine.getSession());
		for(HandshakeCompletedListener listener: listenerList) {
			listener.handshakeCompleted(event);
		}
	}
}
