package com.subgraph.orchid;

import java.util.Set;

import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

public interface Descriptor extends Document {
	enum CacheLocation { NOT_CACHED, CACHED_CACHEFILE, CACHED_JOURNAL }

	HexDigest getDescriptorDigest();
	void setLastListed(long timestamp);
	long getLastListed();
	void setCacheLocation(CacheLocation location);
	CacheLocation getCacheLocation();
	int getBodyLength();
	
	/**
	 * Return the public key used to encrypt EXTEND cells while establishing
	 * a circuit through this router.
	 * 
	 * @return The onion routing protocol key for this router.
	 */
	TorPublicKey getOnionKey();
	byte[] getNTorOnionKey();
	
	/**
	 * Return the IPv4 address of this router.
	 * 
	 * @return The IPv4 address of this router.
	 */
	IPv4Address getAddress();
	
	/**
	 * Return the port on which this node accepts TLS connections
	 * for the main OR protocol, or 0 if no router service is advertised.
	 * 
	 * @return The onion routing port, or 0 if not a router.
	 */
	int getRouterPort();
	Set<String> getFamilyMembers();
	
	/**
	 * Return true if the exit policy of this router permits connections
	 * to the specified destination endpoint.
	 * 
	 * @param address The IPv4 address of the destination.
	 * @param port The destination port.
	 * 
	 * @return True if an exit connection to the specified destination is allowed
	 *         or false otherwise.
	 */
	boolean exitPolicyAccepts(IPv4Address address, int port);
	
	/**
	 * Return true if the exit policy of this router accepts most connections
	 * to the specified destination port.
	 *
	 * @param port The destination port.
	 * @return True if an exit connection to the specified destination port is generally allowed
	 *         or false otherwise.
	 */
	boolean exitPolicyAccepts(int port);
}
