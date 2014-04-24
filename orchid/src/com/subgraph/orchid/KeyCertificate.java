package com.subgraph.orchid;

import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.Timestamp;

/**
 * This class represents a key certificate document as specified in 
 * dir-spec.txt (section 3.1).  These documents are published by
 * directory authorities and bind a long-term identity key to a
 * more temporary signing key. 
 */
public interface KeyCertificate extends Document {
	/**
	 * Return the network address of this directory authority
	 * or <code>null</code> if no address was specified in the certificate.
	 * 
	 * @return The network address of the directory authority this certificate
	 *         belongs to, or <code>null</code> if not available.
	 */
	IPv4Address getDirectoryAddress();
	
	/**
	 * Return the port on which this directory authority answers 
	 * directory requests or 0 if no port was specified in the certificate.
	 * 
	 * @return The port of this directory authority listens on or 0 if
	 *         no port was specified in the certificate.
	 */
	int getDirectoryPort();
	
	/**
	 * Return fingerprint of the authority identity key as specified in
	 * the certificate.
	 * 
	 * @return The authority identity key fingerprint.
	 */
	HexDigest getAuthorityFingerprint();
	
	/**
	 * Return the authority identity public key from the certificate.
	 * 
	 * @return The authority identity public key.
	 */
	TorPublicKey getAuthorityIdentityKey();
	
	/**
	 * Return the authority signing public key from the certificate.
	 * 
	 * @return The authority signing public key.
	 */
	TorPublicKey getAuthoritySigningKey();
	
	/**
	 * Return the time when this document and corresponding keys were
	 * generated.
	 * 
	 * @return The time this document was generated and published.
	 */
	Timestamp getKeyPublishedTime();
	
	/**
	 * Return the time after which this document and signing key are
	 * no longer valid.
	 * 
	 * @return The expiry time of this document and signing key.
	 */
	Timestamp getKeyExpiryTime();
	
	/**
	 * Return <code>true</code> if the current time is past the key
	 * expiry time of this certificate.
	 * 
	 * @return True if this certificate is currently expired.
	 */
	boolean isExpired();
}
