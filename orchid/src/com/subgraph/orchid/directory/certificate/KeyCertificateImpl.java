package com.subgraph.orchid.directory.certificate;

import java.nio.ByteBuffer;

import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.Timestamp;

public class KeyCertificateImpl implements KeyCertificate {
	
	private IPv4Address directoryAddress;
	private int directoryPort;
	private HexDigest fingerprint;
	private TorPublicKey identityKey;
	private Timestamp keyPublished;
	private Timestamp keyExpires;
	private TorPublicKey signingKey;
	private String rawDocumentData;
	
	private boolean hasValidSignature = false;

	void setDirectoryPort(int port) { this.directoryPort = port; }
	void setDirectoryAddress(IPv4Address address) { this.directoryAddress = address; }
	void setAuthorityFingerprint(HexDigest fingerprint) { this.fingerprint = fingerprint;}
	void setAuthorityIdentityKey(TorPublicKey key) { this.identityKey = key; }
	void setAuthoritySigningKey(TorPublicKey key) { this.signingKey = key; }
	void setKeyPublishedTime(Timestamp time) { this.keyPublished = time; }
	void setKeyExpiryTime(Timestamp time) { this.keyExpires = time; }
	void setValidSignature() { hasValidSignature = true;}
	void setRawDocumentData(String rawData) { rawDocumentData = rawData; }
	
	public boolean isValidDocument() {
		return hasValidSignature && (fingerprint != null) && (identityKey != null) &&
			(keyPublished != null) && (keyExpires != null) && (signingKey != null);
	}
	
	public IPv4Address getDirectoryAddress() {
		return directoryAddress;
	}
	
	public int getDirectoryPort() {
		return directoryPort;
	}
	
	public HexDigest getAuthorityFingerprint() {
		return fingerprint;
	}
	
	public TorPublicKey getAuthorityIdentityKey() {
		return identityKey;
	}
	
	public TorPublicKey getAuthoritySigningKey() {
		return signingKey;
	}
	
	public Timestamp getKeyPublishedTime() {
		return keyPublished;
	}
	
	public Timestamp getKeyExpiryTime() {
		return keyExpires;
	}
	
	public boolean isExpired() {
		if(keyExpires != null) {
			return keyExpires.hasPassed();
		} else {
			return false;
		}
	}
	
	public String getRawDocumentData() {
		return rawDocumentData;
	}
	
	public ByteBuffer getRawDocumentBytes() {
		if(getRawDocumentData() == null) {
			return ByteBuffer.allocate(0);
		} else {
			return ByteBuffer.wrap(getRawDocumentData().getBytes(Tor.getDefaultCharset()));
		}
	}
	
	public String toString() {
		return "(Certificate: address="+ directoryAddress +":"+ directoryPort 
			+" fingerprint="+ fingerprint +" published="+ keyPublished +" expires="+ keyExpires +")"+
			"\nident="+ identityKey +" sign="+ signingKey;
	}
}
