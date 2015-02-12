package com.subgraph.orchid;

import java.util.List;
import java.util.Set;

import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.Timestamp;

public interface ConsensusDocument extends Document {
	enum ConsensusFlavor { NS, MICRODESC };
	enum SignatureStatus { STATUS_VERIFIED, STATUS_FAILED, STATUS_NEED_CERTS };
	
	interface RequiredCertificate {
		int getDownloadFailureCount();
		void incrementDownloadFailureCount();
		HexDigest getAuthorityIdentity();
		HexDigest getSigningKey();
	}
	
	ConsensusFlavor getFlavor();
	Timestamp getValidAfterTime();
	Timestamp getFreshUntilTime();
	Timestamp getValidUntilTime();
	int getConsensusMethod();
	int getVoteSeconds();
	int getDistSeconds();
	Set<String> getClientVersions();
	Set<String> getServerVersions();
	boolean isLive();
	List<RouterStatus> getRouterStatusEntries();
	
	SignatureStatus verifySignatures();
	Set<RequiredCertificate> getRequiredCertificates();
	
	HexDigest getSigningHash();
	HexDigest getSigningHash256();
	
	int getCircWindowParameter();
	int getWeightScaleParameter();
	
	int getBandwidthWeight(String tag);
	
	boolean getUseNTorHandshake();
}
