package com.subgraph.orchid.circuits.hs;

public enum IntroductionPointKeyword {
	SERVICE_AUTHENTICATION("service-authentication", 2),
	INTRODUCTION_POINT("introduction-point", 1),
	IP_ADDRESS("ip-address", 1),
	ONION_PORT("onion-port", 1),
	ONION_KEY("onion-key", 0),
	SERVICE_KEY("service-key", 0),
	INTRO_AUTHENTICATION("intro-authentication", 2),
	UNKNOWN_KEYWORD("KEYWORD NOT FOUND", 0);
	
	private final String keyword;
	private final int argumentCount;
	
	IntroductionPointKeyword(String keyword, int argumentCount) {
		this.keyword = keyword;
		this.argumentCount = argumentCount;
	}
	
	String getKeyword() {
		return keyword;
	}
	
	int getArgumentCount() {
		return argumentCount;
	}
	
	static IntroductionPointKeyword findKeyword(String keyword) {
		for(IntroductionPointKeyword k: values()) {
			if(k.getKeyword().equals(keyword)) {
				return k;
			}
		}
		return UNKNOWN_KEYWORD;
	}
}
