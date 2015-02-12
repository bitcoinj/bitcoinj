package com.subgraph.orchid;

import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.Timestamp;
import com.subgraph.orchid.data.exitpolicy.ExitPolicy;

/**
 * Directory information about a single onion router.  This interface
 * provides access to the fields of a router descriptor document which
 * has been published through to Tor directory system.  
 */
public interface RouterDescriptor extends Descriptor {
	/**
	 * Returns the nickname of this router.
	 * 
	 * @return The nickname of this router.
	 */
	String getNickname();
	
	
	/**
	 * Return the port on which this router provides directory related
	 * HTTP connections, or 0 if this node does not provide directory
	 * services.
	 * 
	 * @return The directory service port, or 0 if not a directory server.
	 */
	int getDirectoryPort();
	
	/**
	 * Returns the volume of traffic in bytes per second that this router
	 * is willing to sustain over long periods.
	 * 
	 * @return The average bandwidth of this router in bytes per second.
	 */
	int getAverageBandwidth();
	
	/**
	 * Returns the volume of traffic in bytes per second that this router
	 * is willing to sustain in very short intervals.
	 * 
	 * @return The burst bandwidth of this router in bytes per second.
	 */
	int getBurstBandwidth();
	
	/**
	 * Returns the volume of traffic in bytes per second that this router
	 * is estimated to be able to sustain.
	 * 
	 * @return The observed bandwidth capacity of this router in bytes per second.
	 */
	int getObservedBandwidth();
	
	/**
	 * Return a human-readable string describing the system on which this router
	 * is running, including possibly the operating system version and Tor 
	 * implementation version.
	 * 
	 * @return A string describing the platform this router is running on.
	 */
	String getPlatform();
	
	/**
	 * Return the time this descriptor was generated.
	 * 
	 * @return The time this descriptor was generated.
	 */
	Timestamp getPublishedTime();
	
	/**
	 * Return a fingerprint of the public key of this router.  The fingerprint
	 * is an optional field, so this method may return null if the descriptor 
	 * of the router did not include the 'fingerprint' field.
	 * 
	 * @return The fingerprint of this router, or null if no fingerprint is available.
	 */
	HexDigest getFingerprint();
	
	/**
	 * Return the number of seconds this router has been running.
	 * 
	 * @return The number of seconds this router has been running.
	 */
	int getUptime();
	
	/**
	 * Return the long-term identity and signing public key for this
	 * router.
	 * 
	 * @return The long-term identity and signing public key for this router.
	 */
	TorPublicKey getIdentityKey();
	
	/**
	 * Return a string which describes how to contact the server's administrator.
	 * This is an optional field, so this method will return null if the descriptor
	 * of this router did not include the 'contact' field.
	 * 
	 * @return The contact information for this router, or null if not available.
	 */
	String getContact();
	
	/**
	 * Return true if this router is currently hibernating and not suitable for
	 * building new circuits.
	 * 
	 * @return True if this router is currently hibernating.
	 */
	boolean isHibernating();
	
	/**
	 * Returns true if this router stores and serves hidden service descriptors.
	 * 
	 * @return True if this router is a hidden service directory.
	 */
	boolean isHiddenServiceDirectory();
	
	/**
	 * Return true if this router is running a version of Tor which supports the
	 * newer enhanced DNS logic.  If false, this router should be used for reverse
	 * hostname lookups.
	 * 
	 * @return True if this router supports newer enhanced DNS logic.
	 */
	boolean supportsEventDNS();
	
	/**
	 * Returns true if this router is a directory cache that provides extra-info
	 * documents.
	 * 
	 * @return True if this router provides an extra-info document directory service.
	 */
	boolean cachesExtraInfo();
	
	/**
	 * Return a digest of this router's extra-info document, or null if not 
	 * available.  This is an optional field and will only be present if the
	 * 'extra-info-digest' field was present in the original router descriptor.
	 * 
	 * @return The digest of the router extra-info-document, or null if not available.
	 */
	HexDigest getExtraInfoDigest();
	
	/**
	 * Return true if this router allows single-hop circuits to make exit connections.
	 * 
	 * @return True if this router allows single-hop circuits to make exit connections.
	 */
	boolean allowsSingleHopExits();
	
	/**
	 * Compare two router descriptors and return true if this router descriptor was published
	 * at a later time than the <code>other</code> descriptor.
	 * 
	 * @param other Another router descriptor to compare.
	 * @return True if this descriptor was published later than <code>other</code>
	 */
	boolean isNewerThan(RouterDescriptor other);
		
	ExitPolicy getExitPolicy();
	

}
