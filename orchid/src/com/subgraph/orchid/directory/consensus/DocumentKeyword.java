package com.subgraph.orchid.directory.consensus;

import com.subgraph.orchid.directory.consensus.ConsensusDocumentParser.DocumentSection;

enum DocumentKeyword {
	/*
	 * See dirspec.txt section 3.2
	 */
	NETWORK_STATUS_VERSION("network-status-version", DocumentSection.PREAMBLE, 1),
	VOTE_STATUS("vote-status", DocumentSection.PREAMBLE, 1),
	CONSENSUS_METHODS("consensus-methods", DocumentSection.PREAMBLE, 1, true),
	CONSENSUS_METHOD("consensus-method", DocumentSection.PREAMBLE, 1, false, true),
	PUBLISHED("published", DocumentSection.PREAMBLE, 2, true),
	VALID_AFTER("valid-after",  DocumentSection.PREAMBLE,2),
	FRESH_UNTIL("fresh-until",  DocumentSection.PREAMBLE,2),
	VALID_UNTIL("valid-until",  DocumentSection.PREAMBLE,2),
	VOTING_DELAY("voting-delay",  DocumentSection.PREAMBLE,2),
	CLIENT_VERSIONS("client-versions",  DocumentSection.PREAMBLE,1),
	SERVER_VERSIONS("server-versions",  DocumentSection.PREAMBLE,1),
	KNOWN_FLAGS("known-flags",  DocumentSection.PREAMBLE),
	PARAMS("params",  DocumentSection.PREAMBLE),
	
	DIR_SOURCE("dir-source", DocumentSection.AUTHORITY, 6),
	CONTACT("contact", DocumentSection.AUTHORITY),
	VOTE_DIGEST("vote-digest", DocumentSection.AUTHORITY, 1, false, true),
	
	R("r", DocumentSection.ROUTER_STATUS, 8),
	S("s", DocumentSection.ROUTER_STATUS),
	V("v", DocumentSection.ROUTER_STATUS),
	W("w", DocumentSection.ROUTER_STATUS, 1),
	P("p", DocumentSection.ROUTER_STATUS, 2),
	M("m", DocumentSection.ROUTER_STATUS, 1),
	
	DIRECTORY_FOOTER("directory-footer", DocumentSection.FOOTER),
	BANDWIDTH_WEIGHTS("bandwidth-weights", DocumentSection.FOOTER, 19),
	DIRECTORY_SIGNATURE("directory-signature", DocumentSection.FOOTER, 2),
	
	UNKNOWN_KEYWORD("KEYWORD NOT FOUND");
	
	
	public final static int VARIABLE_ARGUMENT_COUNT = -1;

	private final String keyword;
	private final DocumentSection section;
	private final int argumentCount;
	private final boolean voteOnly;
	private final boolean consensusOnly;
	
	
	DocumentKeyword(String keyword) {
		this(keyword, DocumentSection.NO_SECTION);
	}
	
	DocumentKeyword(String keyword, DocumentSection section) {
		this(keyword, section, VARIABLE_ARGUMENT_COUNT);
	}
	DocumentKeyword(String keyword, DocumentSection section, int argumentCount) {
		this(keyword, section, argumentCount, false);
	}
	
	DocumentKeyword(String keyword, DocumentSection section, int argumentCount, boolean voteOnly) {
		this(keyword, section, argumentCount, voteOnly, false);
	}
	
	
	DocumentKeyword(String keyword, DocumentSection section, int argumentCount, boolean voteOnly, boolean consensusOnly) {
		this.keyword = keyword;
		this.section = section;
		this.argumentCount = argumentCount;
		this.voteOnly = voteOnly;
		this.consensusOnly = consensusOnly;
	}

	static DocumentKeyword findKeyword(String keyword, DocumentSection section) {
		for(DocumentKeyword k : values()) {
			if(k.getKeyword().equals(keyword) && k.getSection().equals(section))
				return k;
		}
		return UNKNOWN_KEYWORD;
	}
	
	public String getKeyword() {
		return keyword;
	}
	
	public DocumentSection getSection() {
		return section;
	}

	public int getArgumentCount() {
		return argumentCount;
	}
	
	public boolean isConsensusOnly() {
		return consensusOnly;
	}
	
	public boolean isVoteOnly() {
		return voteOnly;
	}
	
	
}
