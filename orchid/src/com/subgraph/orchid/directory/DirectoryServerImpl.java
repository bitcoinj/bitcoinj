package com.subgraph.orchid.directory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.RouterStatus;
import com.subgraph.orchid.data.HexDigest;

public class DirectoryServerImpl extends RouterImpl implements DirectoryServer {
	
	private List<KeyCertificate> certificates = new ArrayList<KeyCertificate>();

	private boolean isHiddenServiceAuthority = false;
	private boolean isBridgeAuthority = false;
	private boolean isExtraInfoCache = false;
	private int port;
	private HexDigest v3Ident;
	
	DirectoryServerImpl(RouterStatus status) {
		super(null, status);
	}
	
	void setHiddenServiceAuthority() { isHiddenServiceAuthority = true; }
	void unsetHiddenServiceAuthority() { isHiddenServiceAuthority = false; }
	void setBridgeAuthority() { isBridgeAuthority = true; }
	void setExtraInfoCache() { isExtraInfoCache = true; }
	void setPort(int port) { this.port = port; }
	void setV3Ident(HexDigest fingerprint) { this.v3Ident = fingerprint; }
	
	public boolean isTrustedAuthority() {
		return true;
	}
	
	/**
	 * Return true if this DirectoryServer entry has
	 * complete and valid information.
	 * @return
	 */
	public boolean isValid() {
		return true;
	}
	
	public boolean isV2Authority() {
		return hasFlag("Authority") && hasFlag("V2Dir");
	}
	
	public boolean isV3Authority() {
		return hasFlag("Authority") && v3Ident != null;
	}
	
	public boolean isHiddenServiceAuthority() {
		return isHiddenServiceAuthority;
	}
	
	public boolean isBridgeAuthority() {
		return isBridgeAuthority;
	}
	
	public boolean isExtraInfoCache() {
		return isExtraInfoCache;
	}
	
	public HexDigest getV3Identity() {
		return v3Ident;
	}

	public KeyCertificate getCertificateByFingerprint(HexDigest fingerprint) {
		for(KeyCertificate kc: getCertificates()) {
			if(kc.getAuthoritySigningKey().getFingerprint().equals(fingerprint)) {
				return kc;
			}
		}
		return null;
	}
	
	public List<KeyCertificate> getCertificates() {
		synchronized(certificates) {
			purgeExpiredCertificates();
			purgeOldCertificates();
			return new ArrayList<KeyCertificate>(certificates);
		}
	}

	private void purgeExpiredCertificates() {
		Iterator<KeyCertificate> it = certificates.iterator();
		while(it.hasNext()) {
			KeyCertificate elem = it.next();
			if(elem.isExpired()) {
				it.remove();
			}
		}
	}
	
	private void purgeOldCertificates() {
		if(certificates.size() < 2) {
			return;
		}
		final KeyCertificate newest = getNewestCertificate();
		final Iterator<KeyCertificate> it = certificates.iterator();
		while(it.hasNext()) {
			KeyCertificate elem = it.next();
			if(elem != newest && isMoreThan48HoursOlder(newest, elem)) {
				it.remove();
			}
		}
	}
	
	private KeyCertificate getNewestCertificate() {
		KeyCertificate newest = null;
		for(KeyCertificate kc : certificates) {
			if(newest == null || getPublishedMilliseconds(newest) > getPublishedMilliseconds(kc)) {
				newest = kc;
			}
		}
		return newest;
	}
	
	private boolean isMoreThan48HoursOlder(KeyCertificate newer, KeyCertificate older) {
		final long milliseconds = 48 * 60 * 60 * 1000;
		return (getPublishedMilliseconds(newer) - getPublishedMilliseconds(older)) > milliseconds;
	}
	
	private long getPublishedMilliseconds(KeyCertificate certificate) {
		return certificate.getKeyPublishedTime().getDate().getTime();
	}
	
	public void addCertificate(KeyCertificate certificate) {
		if(!certificate.getAuthorityFingerprint().equals(v3Ident)) {
			throw new IllegalArgumentException("This certificate does not appear to belong to this directory authority");
		}
		synchronized(certificates) {
			certificates.add(certificate);
		}
	}
	
	public String toString() {
		if(v3Ident != null) 
			return "(Directory: "+ getNickname() +" "+ getAddress() +":"+ port +" fingerprint="+ getIdentityHash() +" v3ident="+ 
				v3Ident +")";
		else
			return "(Directory: "+ getNickname() +" "+ getAddress() +":"+ port +" fingerprint="+ getIdentityHash() +")";

	}
}
