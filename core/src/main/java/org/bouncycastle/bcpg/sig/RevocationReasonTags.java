package org.bouncycastle.bcpg.sig;

public interface RevocationReasonTags
{
    public static final byte NO_REASON = 0;              // No reason specified (key revocations or cert revocations)
    public static final byte KEY_SUPERSEDED = 1;         // Key is superseded (key revocations)
    public static final byte KEY_COMPROMISED = 2;        // Key material has been compromised (key revocations)
    public static final byte KEY_RETIRED = 3;            // Key is retired and no longer used (key revocations)
    public static final byte USER_NO_LONGER_VALID = 32;  // User ID information is no longer valid (cert revocations)

    // 100-110 - Private Use
}
