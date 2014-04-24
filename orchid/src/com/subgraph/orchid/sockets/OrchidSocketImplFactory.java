package com.subgraph.orchid.sockets;

import java.net.SocketImpl;
import java.net.SocketImplFactory;

import com.subgraph.orchid.TorClient;

public class OrchidSocketImplFactory implements SocketImplFactory {
	private final TorClient torClient;
	
	public OrchidSocketImplFactory(TorClient torClient) {
		this.torClient = torClient;
	}

	public SocketImpl createSocketImpl() {
		return new OrchidSocketImpl(torClient);
	}
}
