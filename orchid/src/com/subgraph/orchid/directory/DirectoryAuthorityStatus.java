package com.subgraph.orchid.directory;

import java.util.HashSet;
import java.util.Set;

import com.subgraph.orchid.RouterStatus;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.Timestamp;
import com.subgraph.orchid.data.exitpolicy.ExitPorts;

public class DirectoryAuthorityStatus implements RouterStatus {

	private String nickname;
	private HexDigest identity;
	private IPv4Address address;
	private int routerPort;
	private int directoryPort;
	private Set<String> flags = new HashSet<String>();
	private HexDigest v3Ident;
	
	void setV1Authority() { }
	void setHiddenServiceAuthority() { addFlag("HSDir"); }
	void unsetHiddenServiceAuthority() { flags.remove("HSDir"); }
	void setBridgeAuthority() { }
	void unsetV2Authority() { flags.remove("V2Dir"); }
	void setNickname(String name) { nickname = name; }
	void setIdentity(HexDigest identity) { this.identity = identity; }
	void setAddress(IPv4Address address) { this.address = address; }
	void setRouterPort(int port) { this.routerPort = port; }
	void setDirectoryPort(int port) { this.directoryPort = port; }
	void addFlag(String flag) { this.flags.add(flag); }
	void setV3Ident(HexDigest v3Ident) { this.v3Ident = v3Ident; }
	
	DirectoryAuthorityStatus() {
		addFlag("Authority");
		addFlag("V2Dir");
	}
	
	public IPv4Address getAddress() {
		return address;
	}

	public HexDigest getDescriptorDigest() {
		return null;
	}

	public int getDirectoryPort() {
		return directoryPort;
	}

	public int getEstimatedBandwidth() {
		return 0;
	}

	public ExitPorts getExitPorts() {
		return null;
	}

	public HexDigest getIdentity() {
		return identity;
	}

	public boolean hasBandwidth() {
		return false;
	}

	public int getMeasuredBandwidth() {
		return 0;
	}

	public String getNickname() {
		return nickname;
	}

	public Timestamp getPublicationTime() {		
		return null;
	}

	public int getRouterPort() {
		return routerPort;
	}

	public String getVersion() {
		return null;
	}

	public boolean hasFlag(String flag) {
		return flags.contains(flag);
	}

	public boolean isDirectory() {
		return true;
	}

	HexDigest getV3Ident() {
		return v3Ident;
	}
	public HexDigest getMicrodescriptorDigest() {
		return null;
	}
}
