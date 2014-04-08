package org.bouncycastle.asn1.cryptopro;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * <pre>
 * GOST Algorithms OBJECT IDENTIFIERS :
 *    { iso(1) member-body(2) ru(643) rans(2) cryptopro(2)}
 * </pre>
 */
public interface CryptoProObjectIdentifiers
{
    /** Base OID: 1.2.643.2.2 */
    static final ASN1ObjectIdentifier    GOST_id            = new ASN1ObjectIdentifier("1.2.643.2.2");

    /** Gost R3411 OID: 1.2.643.2.2.9 */
    static final ASN1ObjectIdentifier    gostR3411          = GOST_id.branch("9");
    /** Gost R3411 HMAC OID: 1.2.643.2.2.10 */
    static final ASN1ObjectIdentifier    gostR3411Hmac      = GOST_id.branch("10");

    /** Gost R28147 OID: 1.2.643.2.2.21 */
    static final ASN1ObjectIdentifier    gostR28147_gcfb = GOST_id.branch("21");

    /** Gost R28147-89-CryotoPro-A-ParamSet OID: 1.2.643.2.2.31.1 */
    static final ASN1ObjectIdentifier    id_Gost28147_89_CryptoPro_A_ParamSet = GOST_id.branch("31.1");

    /** Gost R28147-89-CryotoPro-B-ParamSet OID: 1.2.643.2.2.31.2 */
    static final ASN1ObjectIdentifier    id_Gost28147_89_CryptoPro_B_ParamSet = GOST_id.branch("31.2");

    /** Gost R28147-89-CryotoPro-C-ParamSet OID: 1.2.643.2.2.31.3 */
    static final ASN1ObjectIdentifier    id_Gost28147_89_CryptoPro_C_ParamSet = GOST_id.branch("31.3");

    /** Gost R28147-89-CryotoPro-D-ParamSet OID: 1.2.643.2.2.31.4 */
    static final ASN1ObjectIdentifier    id_Gost28147_89_CryptoPro_D_ParamSet = GOST_id.branch("31.4");

    /** Gost R3410-94 OID: 1.2.643.2.2.20 */
    static final ASN1ObjectIdentifier    gostR3410_94       = GOST_id.branch("20");
    /** Gost R3410-2001 OID: 1.2.643.2.2.19 */
    static final ASN1ObjectIdentifier    gostR3410_2001     = GOST_id.branch("19");

    /** Gost R3411-94-with-R3410-94 OID: 1.2.643.2.2.4 */
    static final ASN1ObjectIdentifier    gostR3411_94_with_gostR3410_94   = GOST_id.branch("4");
    /** Gost R3411-94-with-R3410-2001 OID: 1.2.643.2.2.3 */
    static final ASN1ObjectIdentifier    gostR3411_94_with_gostR3410_2001 = GOST_id.branch("3");

    /**
     * { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) hashes(30) }
     * <p>
     * Gost R3411-94-CryptoProParamSet OID: 1.2.643.2.2.30.1
     */
    static final ASN1ObjectIdentifier    gostR3411_94_CryptoProParamSet = GOST_id.branch("30.1");

    /**
     * { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) signs(32) }
     * <p>
     * Gost R3410-94-CryptoPro-A OID: 1.2.643.2.2.32.2
     */
    static final ASN1ObjectIdentifier    gostR3410_94_CryptoPro_A     = GOST_id.branch("32.2");
    /** Gost R3410-94-CryptoPro-B OID: 1.2.643.2.2.32.3 */
    static final ASN1ObjectIdentifier    gostR3410_94_CryptoPro_B     = GOST_id.branch("32.3");
    /** Gost R3410-94-CryptoPro-C OID: 1.2.643.2.2.32.4 */
    static final ASN1ObjectIdentifier    gostR3410_94_CryptoPro_C     = GOST_id.branch("32.4");
    /** Gost R3410-94-CryptoPro-D OID: 1.2.643.2.2.32.5 */
    static final ASN1ObjectIdentifier    gostR3410_94_CryptoPro_D     = GOST_id.branch("32.5");

    /**
     * { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) exchanges(33) }
     * <p>
     * Gost R3410-94-CryptoPro-XchA OID: 1.2.643.2.2.33.1
     */
    static final ASN1ObjectIdentifier    gostR3410_94_CryptoPro_XchA  = GOST_id.branch("33.1");
    /** Gost R3410-94-CryptoPro-XchB OID: 1.2.643.2.2.33.2 */
    static final ASN1ObjectIdentifier    gostR3410_94_CryptoPro_XchB  = GOST_id.branch("33.2");
    /** Gost R3410-94-CryptoPro-XchC OID: 1.2.643.2.2.33.3 */
    static final ASN1ObjectIdentifier    gostR3410_94_CryptoPro_XchC  = GOST_id.branch("33.3");

    /**
     * { iso(1) member-body(2)ru(643) rans(2) cryptopro(2) ecc-signs(35) }
     * <p>
     * Gost R3410-2001-CryptoPro-A OID: 1.2.643.2.2.35.1
     */
    static final ASN1ObjectIdentifier    gostR3410_2001_CryptoPro_A = GOST_id.branch("35.1");
    /** Gost R3410-2001-CryptoPro-B OID: 1.2.643.2.2.35.2 */
    static final ASN1ObjectIdentifier    gostR3410_2001_CryptoPro_B = GOST_id.branch("35.2");
    /** Gost R3410-2001-CryptoPro-C OID: 1.2.643.2.2.35.3 */
    static final ASN1ObjectIdentifier    gostR3410_2001_CryptoPro_C = GOST_id.branch("35.3");

    /**
     * { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) ecc-exchanges(36) }
     * <p>
     * Gost R3410-2001-CryptoPro-XchA OID: 1.2.643.2.2.36.0
     */
    static final ASN1ObjectIdentifier    gostR3410_2001_CryptoPro_XchA  = GOST_id.branch("36.0");
    /** Gost R3410-2001-CryptoPro-XchA OID: 1.2.643.2.2.36.1 */
    static final ASN1ObjectIdentifier    gostR3410_2001_CryptoPro_XchB  = GOST_id.branch("36.1");
    
    /** Gost R3410-ElSqDH3410-default OID: 1.2.643.2.2.36.0 */
    static final ASN1ObjectIdentifier    gost_ElSgDH3410_default    = GOST_id.branch("36.0");
    /** Gost R3410-ElSqDH3410-1 OID: 1.2.643.2.2.36.1 */
    static final ASN1ObjectIdentifier    gost_ElSgDH3410_1          = GOST_id.branch("36.1");
}
