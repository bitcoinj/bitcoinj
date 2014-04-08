package org.bouncycastle.asn1.gnu;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *  GNU project OID collection<p>
 *  { iso(1) identifier-organization(3) dod(6) internet(1) private(4) } == IETF defined things
 */
public interface GNUObjectIdentifiers
{
    /** 1.3.6.1.4.1.11591.1 -- used by GNU Radius */
    public static final ASN1ObjectIdentifier GNU      = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.1"); // GNU Radius
    /** 1.3.6.1.4.1.11591.2 -- used by GNU PG */
    public static final ASN1ObjectIdentifier GnuPG    = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.2"); // GnuPG (Ägypten)
    /** 1.3.6.1.4.1.11591.2.1 -- notation */
    public static final ASN1ObjectIdentifier notation = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.2.1"); // notation
    /** 1.3.6.1.4.1.11591.2.1.1 -- pkaAddress */
    public static final ASN1ObjectIdentifier pkaAddress = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.2.1.1"); // pkaAddress
    /** 1.3.6.1.4.1.11591.3 -- GNU Radar */
    public static final ASN1ObjectIdentifier GnuRadar = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.3"); // GNU Radar
    /** 1.3.6.1.4.1.11591.12 -- digestAlgorithm */
    public static final ASN1ObjectIdentifier digestAlgorithm = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.12"); // digestAlgorithm
    /** 1.3.6.1.4.1.11591.12.2 -- TIGER/192 */
    public static final ASN1ObjectIdentifier Tiger_192 = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.12.2"); // TIGER/192
    /** 1.3.6.1.4.1.11591.13 -- encryptionAlgorithm */
    public static final ASN1ObjectIdentifier encryptionAlgorithm = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13"); // encryptionAlgorithm
    /** 1.3.6.1.4.1.11591.13.2 -- Serpent */
    public static final ASN1ObjectIdentifier Serpent = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2"); // Serpent
    /** 1.3.6.1.4.1.11591.13.2.1 -- Serpent-128-ECB */
    public static final ASN1ObjectIdentifier Serpent_128_ECB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.1"); // Serpent-128-ECB
    /** 1.3.6.1.4.1.11591.13.2.2 -- Serpent-128-CBC */
    public static final ASN1ObjectIdentifier Serpent_128_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.2"); // Serpent-128-CBC
    /** 1.3.6.1.4.1.11591.13.2.3 -- Serpent-128-OFB */
    public static final ASN1ObjectIdentifier Serpent_128_OFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.3"); // Serpent-128-OFB
    /** 1.3.6.1.4.1.11591.13.2.4 -- Serpent-128-CFB */
    public static final ASN1ObjectIdentifier Serpent_128_CFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.4"); // Serpent-128-CFB
    /** 1.3.6.1.4.1.11591.13.2.21 -- Serpent-192-ECB */
    public static final ASN1ObjectIdentifier Serpent_192_ECB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.21"); // Serpent-192-ECB
    /** 1.3.6.1.4.1.11591.13.2.22 -- Serpent-192-CCB */
    public static final ASN1ObjectIdentifier Serpent_192_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.22"); // Serpent-192-CBC
    /** 1.3.6.1.4.1.11591.13.2.23 -- Serpent-192-OFB */
    public static final ASN1ObjectIdentifier Serpent_192_OFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.23"); // Serpent-192-OFB
    /** 1.3.6.1.4.1.11591.13.2.24 -- Serpent-192-CFB */
    public static final ASN1ObjectIdentifier Serpent_192_CFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.24"); // Serpent-192-CFB
    /** 1.3.6.1.4.1.11591.13.2.41 -- Serpent-256-ECB */
    public static final ASN1ObjectIdentifier Serpent_256_ECB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.41"); // Serpent-256-ECB
    /** 1.3.6.1.4.1.11591.13.2.42 -- Serpent-256-CBC */
    public static final ASN1ObjectIdentifier Serpent_256_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.42"); // Serpent-256-CBC
    /** 1.3.6.1.4.1.11591.13.2.43 -- Serpent-256-OFB */
    public static final ASN1ObjectIdentifier Serpent_256_OFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.43"); // Serpent-256-OFB
    /** 1.3.6.1.4.1.11591.13.2.44 -- Serpent-256-CFB */
    public static final ASN1ObjectIdentifier Serpent_256_CFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.44"); // Serpent-256-CFB

    /** 1.3.6.1.4.1.11591.14 -- CRC algorithms */
    public static final ASN1ObjectIdentifier CRC = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.14"); // CRC algorithms
    /** 1.3.6.1.4.1.11591.14,1 -- CRC32 */
    public static final ASN1ObjectIdentifier CRC32 = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.14.1"); // CRC 32
}
