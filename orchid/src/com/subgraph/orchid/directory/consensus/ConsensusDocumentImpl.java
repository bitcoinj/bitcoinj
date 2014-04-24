package com.subgraph.orchid.directory.consensus;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.RouterStatus;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.VoteAuthorityEntry;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.crypto.TorSignature.DigestAlgorithm;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.Timestamp;
import com.subgraph.orchid.directory.TrustedAuthorities;

public class ConsensusDocumentImpl implements ConsensusDocument {
	
	enum SignatureVerifyStatus { STATUS_UNVERIFIED, STATUS_NEED_CERTS, STATUS_VERIFIED };
	
	private final static Logger logger = Logger.getLogger(ConsensusDocumentImpl.class.getName());
	
	private final static String BW_WEIGHT_SCALE_PARAM = "bwweightscale";
	private final static int BW_WEIGHT_SCALE_DEFAULT = 10000;
	private final static int BW_WEIGHT_SCALE_MIN = 1;
	private final static int BW_WEIGHT_SCALE_MAX = Integer.MAX_VALUE;
	
	private final static String CIRCWINDOW_PARAM = "circwindow";
	private final static int CIRCWINDOW_DEFAULT = 1000;
	private final static int CIRCWINDOW_MIN = 100;
	private final static int CIRCWINDOW_MAX = 1000;
	
	private final static String USE_NTOR_HANDSHAKE_PARAM = "UseNTorHandshake";
	
	private Set<RequiredCertificate> requiredCertificates = new HashSet<RequiredCertificate>();
	
	
	private int consensusMethod;
	private ConsensusFlavor flavor;
	private Timestamp validAfter;
	private Timestamp freshUntil;
	private Timestamp validUntil;
	private int distDelaySeconds;
	private int voteDelaySeconds;
	private Set<String> clientVersions;
	private Set<String> serverVersions;
	private Set<String> knownFlags;
	private HexDigest signingHash;
	private HexDigest signingHash256;
	private Map<HexDigest, VoteAuthorityEntry> voteAuthorityEntries;
	private List<RouterStatus> routerStatusEntries;
	private Map<String, Integer> bandwidthWeights;
	private Map<String, Integer> parameters;
	private int signatureCount;
	private boolean isFirstCallToVerifySignatures = true;
	private String rawDocumentData;
	
	void setConsensusFlavor(ConsensusFlavor flavor) { this.flavor = flavor; }
	void setConsensusMethod(int method) { consensusMethod = method; }
	void setValidAfter(Timestamp ts) { validAfter = ts; }
	void setFreshUntil(Timestamp ts) { freshUntil = ts; }
	void setValidUntil(Timestamp ts) { validUntil = ts; }
	void setDistDelaySeconds(int seconds) { distDelaySeconds = seconds; }
	void setVoteDelaySeconds(int seconds) { voteDelaySeconds = seconds; }
	void addClientVersion(String version) { clientVersions.add(version); }
	void addServerVersion(String version) { serverVersions.add(version); }
	void addParameter(String name, int value) { parameters.put(name, value); }
	void addBandwidthWeight(String name, int value) { bandwidthWeights.put(name, value); }
		
	void addSignature(DirectorySignature signature) {
		final VoteAuthorityEntry voteAuthority = voteAuthorityEntries.get(signature.getIdentityDigest());
		if(voteAuthority == null) {
			logger.warning("Consensus contains signature for source not declared in authority section: "+ signature.getIdentityDigest());
			return;
		}
		final List<DirectorySignature> signatures = voteAuthority.getSignatures();
		final DigestAlgorithm newSignatureAlgorithm = signature.getSignature().getDigestAlgorithm();
		for(DirectorySignature sig: signatures) {
			DigestAlgorithm algo = sig.getSignature().getDigestAlgorithm();
			if(algo.equals(newSignatureAlgorithm)) {
				logger.warning("Consensus contains two or more signatures for same source with same algorithm");
				return;
			}
		}
		signatureCount += 1;
		signatures.add(signature);
	}

	void setSigningHash(HexDigest hash) { signingHash = hash; }
	void setSigningHash256(HexDigest hash) { signingHash256 = hash; }
	void setRawDocumentData(String rawData) { rawDocumentData = rawData; }
	
	ConsensusDocumentImpl() {
		clientVersions = new HashSet<String>();
		serverVersions = new HashSet<String>();
		knownFlags = new HashSet<String>();
		voteAuthorityEntries = new HashMap<HexDigest, VoteAuthorityEntry>();
		routerStatusEntries = new ArrayList<RouterStatus>();
		bandwidthWeights = new HashMap<String, Integer>();
		parameters = new HashMap<String, Integer>();
	}
	
	void addKnownFlag(String flag) {
		knownFlags.add(flag);
	}
	
	void addVoteAuthorityEntry(VoteAuthorityEntry entry) {
		voteAuthorityEntries.put(entry.getIdentity(), entry);
	}
	
	void addRouterStatusEntry(RouterStatusImpl entry) {
		routerStatusEntries.add(entry);
	}
	
	public ConsensusFlavor getFlavor() {
		return flavor;
	}

	public Timestamp getValidAfterTime() {
		return validAfter;
	}
	
	public Timestamp getFreshUntilTime() {
		return freshUntil;
	}
	
	public Timestamp getValidUntilTime() {
		return validUntil;
	}
	
	public int getConsensusMethod() {
		return consensusMethod;
	}
	
	public int getVoteSeconds() {
		return voteDelaySeconds;
	}
	
	public int getDistSeconds() {
		return distDelaySeconds;
	}
	
	public Set<String> getClientVersions() {
		return clientVersions;
	}
	
	public Set<String> getServerVersions() {
		return serverVersions;
	}
	
	public boolean isLive() {
		if(validUntil == null) {
			return false;
		} else {
			return !validUntil.hasPassed(); 
		}
	}
	
	public List<RouterStatus> getRouterStatusEntries() {
		return Collections.unmodifiableList(routerStatusEntries);
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

	public boolean isValidDocument() {
		return (validAfter != null) && (freshUntil != null) && (validUntil != null) &&
		(voteDelaySeconds > 0) && (distDelaySeconds > 0) && (signingHash != null) &&
		(signatureCount > 0);
	}
	
	public HexDigest getSigningHash() {
		return signingHash;
	}
	
	public HexDigest getSigningHash256() {
		return signingHash256;
	}
	
	public synchronized SignatureStatus verifySignatures() {
		boolean firstCall = isFirstCallToVerifySignatures;
		isFirstCallToVerifySignatures = false;
		requiredCertificates.clear();
		int verifiedCount = 0;
		int certsNeededCount = 0;
		final int v3Count = TrustedAuthorities.getInstance().getV3AuthorityServerCount();
		final int required = (v3Count / 2) + 1;
		
		for(VoteAuthorityEntry entry: voteAuthorityEntries.values()) {
			switch(verifySingleAuthority(entry)) {
			case STATUS_FAILED:
				break;
			case STATUS_NEED_CERTS:
				certsNeededCount += 1;
				break;
			case STATUS_VERIFIED:
				verifiedCount += 1;
				break;
			}
		}
		
		if(verifiedCount >= required) {
			return SignatureStatus.STATUS_VERIFIED;
		} else if(verifiedCount + certsNeededCount >= required) {
			if(firstCall) {
				logger.info("Certificates need to be retrieved to verify consensus");
			}
			return SignatureStatus.STATUS_NEED_CERTS;
		} else {
			return SignatureStatus.STATUS_FAILED;
		}
	}

	private SignatureStatus verifySingleAuthority(VoteAuthorityEntry authority) {
		
		boolean certsNeeded = false;
		boolean validSignature = false;
		
		for(DirectorySignature s: authority.getSignatures()) {
			DirectoryServer trusted = TrustedAuthorities.getInstance().getAuthorityServerByIdentity(s.getIdentityDigest());
			if(trusted == null) {
				logger.warning("Consensus signed by unrecognized directory authority: "+ s.getIdentityDigest());
				return SignatureStatus.STATUS_FAILED;
			} else {
				switch(verifySignatureForTrustedAuthority(trusted, s)) {
				case STATUS_NEED_CERTS:
					certsNeeded = true;
					break;
				case STATUS_VERIFIED:
					validSignature = true;
					break;
				default:
					break;
				}
			}
		}
		
		if(validSignature) {
			return SignatureStatus.STATUS_VERIFIED;
		} else if(certsNeeded) {
			return SignatureStatus.STATUS_NEED_CERTS;
		} else {
			return SignatureStatus.STATUS_FAILED;
		}
	}
	
	private SignatureStatus verifySignatureForTrustedAuthority(DirectoryServer trustedAuthority, DirectorySignature signature) {
		final KeyCertificate certificate = trustedAuthority.getCertificateByFingerprint(signature.getSigningKeyDigest());
		if(certificate == null) {
			logger.fine("Missing certificate for signing key: "+ signature.getSigningKeyDigest());
			addRequiredCertificateForSignature(signature);
			return SignatureStatus.STATUS_NEED_CERTS;
		}
		if(certificate.isExpired()) {
			return SignatureStatus.STATUS_FAILED;
		}
		
		final TorPublicKey signingKey = certificate.getAuthoritySigningKey();
		final HexDigest d = (signature.useSha256()) ? signingHash256 : signingHash;
		if(!signingKey.verifySignature(signature.getSignature(), d)) {
			logger.warning("Signature failed on consensus for signing key: "+ signature.getSigningKeyDigest());
			return SignatureStatus.STATUS_FAILED;
		}
		return SignatureStatus.STATUS_VERIFIED;
	}

	public Set<RequiredCertificate> getRequiredCertificates() {
		return requiredCertificates;
	}

	private void addRequiredCertificateForSignature(DirectorySignature signature) {
		requiredCertificates.add(new RequiredCertificateImpl(signature.getIdentityDigest(), signature.getSigningKeyDigest()));
	}

	public boolean equals(Object o) {
		if(!(o instanceof ConsensusDocumentImpl))
			return false;
		final ConsensusDocumentImpl other = (ConsensusDocumentImpl) o;
		return other.getSigningHash().equals(signingHash);
	}
	
	public int hashCode() {
		return (signingHash == null) ? 0 : signingHash.hashCode();
	}
	
	private int getParameterValue(String name, int defaultValue, int minValue, int maxValue) {
		if(!parameters.containsKey(name)) {
			return defaultValue;
		}
		final int value = parameters.get(name);
		if(value < minValue) {
			return minValue;
		} else if(value > maxValue) {
			return maxValue;
		} else {
			return value;
		}
	}
	
	private boolean getBooleanParameterValue(String name, boolean defaultValue) {
		if(!parameters.containsKey(name)) {
			return defaultValue;
		}
		final int value = parameters.get(name);
		return value != 0;
	}
	
	public int getCircWindowParameter() {
		return getParameterValue(CIRCWINDOW_PARAM, CIRCWINDOW_DEFAULT, CIRCWINDOW_MIN, CIRCWINDOW_MAX);
	}
	
	public int getWeightScaleParameter() {
		return getParameterValue(BW_WEIGHT_SCALE_PARAM, BW_WEIGHT_SCALE_DEFAULT, BW_WEIGHT_SCALE_MIN, BW_WEIGHT_SCALE_MAX);
	}
	
	public int getBandwidthWeight(String tag) {
		if(bandwidthWeights.containsKey(tag)) {
			return bandwidthWeights.get(tag);
		} else {
			return -1;
		}
	}
	
	public boolean getUseNTorHandshake() {
		return getBooleanParameterValue(USE_NTOR_HANDSHAKE_PARAM, false);
	}
}
