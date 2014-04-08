package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *  iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle
 * <p>
 *  1.3.6.1.4.1.22554
 */
public interface BCObjectIdentifiers
{
    /**
     *  iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle
     *<p>
     *  1.3.6.1.4.1.22554
     */
    public static final ASN1ObjectIdentifier bc = new ASN1ObjectIdentifier("1.3.6.1.4.1.22554");

    /**
     * pbe(1) algorithms
     * <p>
     * 1.3.6.1.4.1.22554.1
     */
    public static final ASN1ObjectIdentifier bc_pbe        = bc.branch("1");

    /**
     * SHA-1(1)
     * <p>
     * 1.3.6.1.4.1.22554.1.1
     */
    public static final ASN1ObjectIdentifier bc_pbe_sha1   = bc_pbe.branch("1");

    /** SHA-2.SHA-256; 1.3.6.1.4.1.22554.1.2.1 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256 = bc_pbe.branch("2.1");
    /** SHA-2.SHA-384; 1.3.6.1.4.1.22554.1.2.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha384 = bc_pbe.branch("2.2");
    /** SHA-2.SHA-512; 1.3.6.1.4.1.22554.1.2.3 */
    public static final ASN1ObjectIdentifier bc_pbe_sha512 = bc_pbe.branch("2.3");
    /** SHA-2.SHA-224; 1.3.6.1.4.1.22554.1.2.4 */
    public static final ASN1ObjectIdentifier bc_pbe_sha224 = bc_pbe.branch("2.4");

    /**
     * PKCS-5(1)|PKCS-12(2)
     */
    /** SHA-1.PKCS5;  1.3.6.1.4.1.22554.1.1.1 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs5    = bc_pbe_sha1.branch("1");
    /** SHA-1.PKCS12; 1.3.6.1.4.1.22554.1.1.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs12   = bc_pbe_sha1.branch("2");

    /** SHA-256.PKCS12; 1.3.6.1.4.1.22554.1.2.1.1 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs5  = bc_pbe_sha256.branch("1");
    /** SHA-256.PKCS12; 1.3.6.1.4.1.22554.1.2.1.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs12 = bc_pbe_sha256.branch("2");

    /**
     * AES(1) . (CBC-128(2)|CBC-192(22)|CBC-256(42))
     */
    /** 1.3.6.1.4.1.22554.1.1.2.1.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes128_cbc   = bc_pbe_sha1_pkcs12.branch("1.2");
    /** 1.3.6.1.4.1.22554.1.1.2.1.22 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes192_cbc   = bc_pbe_sha1_pkcs12.branch("1.22");
    /** 1.3.6.1.4.1.22554.1.1.2.1.42 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes256_cbc   = bc_pbe_sha1_pkcs12.branch("1.42");

    /** 1.3.6.1.4.1.22554.1.1.2.2.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes128_cbc = bc_pbe_sha256_pkcs12.branch("1.2");
    /** 1.3.6.1.4.1.22554.1.1.2.2.22 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes192_cbc = bc_pbe_sha256_pkcs12.branch("1.22");
    /** 1.3.6.1.4.1.22554.1.1.2.2.42 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes256_cbc = bc_pbe_sha256_pkcs12.branch("1.42");
}
