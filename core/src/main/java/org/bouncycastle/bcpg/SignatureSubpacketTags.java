package org.bouncycastle.bcpg;

/**
 * Basic PGP signature sub-packet tag types.
 */
public interface SignatureSubpacketTags 
{
    public static final int CREATION_TIME = 2;         // signature creation time
    public static final int EXPIRE_TIME = 3;           // signature expiration time
    public static final int EXPORTABLE = 4;            // exportable certification
    public static final int TRUST_SIG = 5;             // trust signature
    public static final int REG_EXP = 6;               // regular expression
    public static final int REVOCABLE = 7;             // revocable
    public static final int KEY_EXPIRE_TIME = 9;       // key expiration time
    public static final int PLACEHOLDER = 10;          // placeholder for backward compatibility
    public static final int PREFERRED_SYM_ALGS = 11;   // preferred symmetric algorithms
    public static final int REVOCATION_KEY = 12;       // revocation key
    public static final int ISSUER_KEY_ID = 16;        // issuer key ID
    public static final int NOTATION_DATA = 20;        // notation data
    public static final int PREFERRED_HASH_ALGS = 21;  // preferred hash algorithms
    public static final int PREFERRED_COMP_ALGS = 22;  // preferred compression algorithms
    public static final int KEY_SERVER_PREFS = 23;     // key server preferences
    public static final int PREFERRED_KEY_SERV = 24;   // preferred key server
    public static final int PRIMARY_USER_ID = 25;      // primary user id
    public static final int POLICY_URL = 26;           // policy URL
    public static final int KEY_FLAGS = 27;            // key flags
    public static final int SIGNER_USER_ID = 28;       // signer's user id
    public static final int REVOCATION_REASON = 29;    // reason for revocation
    public static final int FEATURES = 30;             // features
    public static final int SIGNATURE_TARGET = 31;     // signature target
    public static final int EMBEDDED_SIGNATURE = 32;   // embedded signature
}
