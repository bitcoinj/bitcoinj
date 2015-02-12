package com.subgraph.orchid.directory.certificate;

public enum KeyCertificateKeyword {
	/*
	 * See dir-spec.txt
	 * Section 3.1 Key certificates
	 */
	DIR_KEY_CERTIFICATE_VERSION("dir-key-certificate-version", 1),
	DIR_ADDRESS("dir-address", 1),
	FINGERPRINT("fingerprint", 1),
	DIR_IDENTITY_KEY("dir-identity-key", 0),
	DIR_KEY_PUBLISHED("dir-key-published", 2),
	DIR_KEY_EXPIRES("dir-key-expires", 2),
	DIR_SIGNING_KEY("dir-signing-key", 0),
	DIR_KEY_CROSSCERT("dir-key-crosscert", 0),
	DIR_KEY_CERTIFICATION("dir-key-certification", 0),
	UNKNOWN_KEYWORD("KEYWORD NOT FOUND", 0);
	
	private final String keyword;
	private final int argumentCount;
	
	KeyCertificateKeyword(String keyword, int argumentCount) {
		this.keyword = keyword;
		this.argumentCount = argumentCount;
	}
	
	String getKeyword() {
		return keyword;
	}
	
	int getArgumentCount() {
		return argumentCount;
	}
	
	static KeyCertificateKeyword findKeyword(String keyword) {
		for(KeyCertificateKeyword k: values()) 
			if(k.getKeyword().equals(keyword))
				return k;
		return UNKNOWN_KEYWORD;
	}
	
}
