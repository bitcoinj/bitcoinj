package com.subgraph.orchid.directory.router;

public enum RouterDescriptorKeyword {
	/*
	 * See dir-spec.txt 
	 * Section 2.1. Router descriptor format
	 */
	ROUTER("router", 5),
	BANDWIDTH("bandwidth", 3),
	PLATFORM("platform"),
	PUBLISHED("published", 2),
	FINGERPRINT("fingerprint", 10),
	HIBERNATING("hibernating", 1),
	UPTIME("uptime", 1),
	ONION_KEY("onion-key", 0),
	NTOR_ONION_KEY("ntor-onion-key", 1),
	SIGNING_KEY("signing-key", 0),
	ACCEPT("accept", 1),
	REJECT("reject", 1),
	ROUTER_SIGNATURE("router-signature", 0),
	CONTACT("contact"),
	FAMILY("family"),
	READ_HISTORY("read-history"),
	WRITE_HISTORY("write-history"),
	EVENTDNS("eventdns", 1),
	CACHES_EXTRA_INFO("caches-extra-info", 0),
	EXTRA_INFO_DIGEST("extra-info-digest", 1),
	HIDDEN_SERVICE_DIR("hidden-service-dir"),
	PROTOCOLS("protocols"),
	ALLOW_SINGLE_HOP_EXITS("allow-single-hop-exits", 0),
	UNKNOWN_KEYWORD("KEYWORD NOT FOUND");
	
	public final static int VARIABLE_ARGUMENT_COUNT = -1;

	private final String keyword;
	private final int argumentCount;
	
	RouterDescriptorKeyword(String keyword) {
		this(keyword, VARIABLE_ARGUMENT_COUNT);
	}
	
	RouterDescriptorKeyword(String keyword, int argumentCount) {
		this.keyword = keyword;
		this.argumentCount = argumentCount;
	}
	
	String getKeyword() {
		return keyword;
	}
	
	int getArgumentCount() {
		return argumentCount;
	}
	
	static RouterDescriptorKeyword findKeyword(String keyword) {
		for(RouterDescriptorKeyword k: values()) 
			if(k.getKeyword().equals(keyword)) 
				return k;
		
		return UNKNOWN_KEYWORD;
	}

}
