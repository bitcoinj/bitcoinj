package com.subgraph.orchid.circuits.hs;

public enum HSDescriptorKeyword {
	RENDEZVOUS_SERVICE_DESCRIPTOR("rendezvous-service-descriptor", 1),
	VERSION("version", 1),
	PERMANENT_KEY("permanent-key", 0),
	SECRET_ID_PART("secret-id-part", 1),
	PUBLICATION_TIME("publication-time", 2),
	PROTOCOL_VERSIONS("protocol-versions", 2),
	INTRODUCTION_POINTS("introduction-points", 0),
	SIGNATURE("signature", 0),
	UNKNOWN_KEYWORD("KEYWORD NOT FOUND", 0);
	
	private final String keyword;
	private final int argumentCount;
	
	HSDescriptorKeyword(String keyword, int argumentCount) {
		this.keyword = keyword;
		this.argumentCount = argumentCount;
	}
	
	String getKeyword() {
		return keyword;
	}
	
	int getArgumentCount() {
		return argumentCount;
	}
	
	static HSDescriptorKeyword findKeyword(String keyword) {
		for(HSDescriptorKeyword k: values()) {
			if(k.getKeyword().equals(keyword)) {
				return k;
			}
		}
		return UNKNOWN_KEYWORD;
	}
}
