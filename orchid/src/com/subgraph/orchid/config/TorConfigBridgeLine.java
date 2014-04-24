package com.subgraph.orchid.config;

import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

public class TorConfigBridgeLine {
	
	private final IPv4Address address;
	private final int port;
	private final HexDigest fingerprint;

	TorConfigBridgeLine(IPv4Address address, int port, HexDigest fingerprint) {
		this.address = address;
		this.port = port;
		this.fingerprint = fingerprint;
	}
	
	public IPv4Address getAddress() {
		return address;
	}
	
	public int getPort() {
		return port;
	}
	
	public HexDigest getFingerprint() {
		return fingerprint;
	}
}
