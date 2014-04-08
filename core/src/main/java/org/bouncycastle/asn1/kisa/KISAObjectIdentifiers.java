package org.bouncycastle.asn1.kisa;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Korea Information Security Agency (KISA)
 * ({iso(1) member-body(2) kr(410) kisa(200004)})
 * <p>
 * See <a href="http://tools.ietf.org/html/rfc4010">RFC 4010</a>
 * Use of the SEED Encryption Algorithm
 * in Cryptographic Message Syntax (CMS),
 * and <a href="http://tools.ietf.org/html/rfc4269">RFC 4269</a>
 * The SEED Encryption Algorithm
 */
public interface KISAObjectIdentifiers
{
    /** RFC 4010, 4269: id-seedCBC; OID 1.2.410.200004.1.4 */
    static final ASN1ObjectIdentifier id_seedCBC = new ASN1ObjectIdentifier("1.2.410.200004.1.4");

    /** RFC 4269: id-seedMAC; OID 1.2.410.200004.1.7 */
    static final ASN1ObjectIdentifier id_seedMAC = new ASN1ObjectIdentifier("1.2.410.200004.1.7");

    /** RFC 4269: pbeWithSHA1AndSEED-CBC; OID 1.2.410.200004.1.15 */
    static final ASN1ObjectIdentifier pbeWithSHA1AndSEED_CBC = new ASN1ObjectIdentifier("1.2.410.200004.1.15");

    /** RFC 4010: id-npki-app-cmsSeed-wrap; OID 1.2.410.200004.7.1.1.1 */
    static final ASN1ObjectIdentifier id_npki_app_cmsSeed_wrap = new ASN1ObjectIdentifier("1.2.410.200004.7.1.1.1");

    /** RFC 4010: SeedEncryptionAlgorithmInCMS; OID 1.2.840.113549.1.9.16.0.24 */
    static final ASN1ObjectIdentifier id_mod_cms_seed = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.0.24");
}
