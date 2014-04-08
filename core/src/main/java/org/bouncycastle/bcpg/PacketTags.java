package org.bouncycastle.bcpg;

/**
 * Basic PGP packet tag types.
 */
public interface PacketTags 
{
      public static final int RESERVED =  0 ;                //  Reserved - a packet tag must not have this value
      public static final int PUBLIC_KEY_ENC_SESSION = 1;    // Public-Key Encrypted Session Key Packet
      public static final int SIGNATURE = 2;                 // Signature Packet
      public static final int SYMMETRIC_KEY_ENC_SESSION = 3; // Symmetric-Key Encrypted Session Key Packet
      public static final int ONE_PASS_SIGNATURE = 4 ;       // One-Pass Signature Packet
      public static final int SECRET_KEY = 5;                // Secret Key Packet
      public static final int PUBLIC_KEY = 6 ;               // Public Key Packet
      public static final int SECRET_SUBKEY = 7;             // Secret Subkey Packet
      public static final int COMPRESSED_DATA = 8;           // Compressed Data Packet
      public static final int SYMMETRIC_KEY_ENC = 9;         // Symmetrically Encrypted Data Packet
      public static final int MARKER = 10;                   // Marker Packet
      public static final int LITERAL_DATA = 11;             // Literal Data Packet
      public static final int TRUST = 12;                    // Trust Packet
      public static final int USER_ID = 13;                  // User ID Packet
      public static final int PUBLIC_SUBKEY = 14;            // Public Subkey Packet
      public static final int USER_ATTRIBUTE = 17;           // User attribute
      public static final int SYM_ENC_INTEGRITY_PRO = 18;    // Symmetric encrypted, integrity protected
      public static final int MOD_DETECTION_CODE = 19;       // Modification detection code
      
      public static final int EXPERIMENTAL_1 = 60;           // Private or Experimental Values
      public static final int EXPERIMENTAL_2 = 61;
      public static final int EXPERIMENTAL_3 = 62;
      public static final int EXPERIMENTAL_4 = 63;
}
