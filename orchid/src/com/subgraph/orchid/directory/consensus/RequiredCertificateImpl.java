package com.subgraph.orchid.directory.consensus;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.data.HexDigest;

public class RequiredCertificateImpl implements ConsensusDocument.RequiredCertificate {

	private final HexDigest identity;
	private final HexDigest signingKey;

	private int downloadFailureCount;
	
	public RequiredCertificateImpl(HexDigest identity, HexDigest signingKey) {
		this.identity = identity;
		this.signingKey = signingKey;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((identity == null) ? 0 : identity.hashCode());
		result = prime * result
				+ ((signingKey == null) ? 0 : signingKey.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RequiredCertificateImpl other = (RequiredCertificateImpl) obj;
		if (identity == null) {
			if (other.identity != null)
				return false;
		} else if (!identity.equals(other.identity))
			return false;
		if (signingKey == null) {
			if (other.signingKey != null)
				return false;
		} else if (!signingKey.equals(other.signingKey))
			return false;
		return true;
	}

	public void incrementDownloadFailureCount() {
		downloadFailureCount += 1;
	}
	
	public int getDownloadFailureCount() {
		return downloadFailureCount;
	}

	public HexDigest getAuthorityIdentity() {
		return identity;
	}

	public HexDigest getSigningKey() {
		return signingKey;
	}
	
	

}
