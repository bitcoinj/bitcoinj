package org.bouncycastle.asn1.sec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * Certicom object identifiers
 * <pre>
 *  ellipticCurve OBJECT IDENTIFIER ::= {
 *        iso(1) identified-organization(3) certicom(132) curve(0)
 *  }
 * </pre>
 */
public interface SECObjectIdentifiers
{
    /** Base OID: 1.3.132.0 */
    static final ASN1ObjectIdentifier ellipticCurve = new ASN1ObjectIdentifier("1.3.132.0");

    /**  sect163k1 OID: 1.3.132.0.1 */
    static final ASN1ObjectIdentifier sect163k1 = ellipticCurve.branch("1");
    /**  sect163r1 OID: 1.3.132.0.2 */
    static final ASN1ObjectIdentifier sect163r1 = ellipticCurve.branch("2");
    /**  sect239k1 OID: 1.3.132.0.3 */
    static final ASN1ObjectIdentifier sect239k1 = ellipticCurve.branch("3");
    /**  sect113r1 OID: 1.3.132.0.4 */
    static final ASN1ObjectIdentifier sect113r1 = ellipticCurve.branch("4");
    /**  sect113r2 OID: 1.3.132.0.5 */
    static final ASN1ObjectIdentifier sect113r2 = ellipticCurve.branch("5");
    /**  secp112r1 OID: 1.3.132.0.6 */
    static final ASN1ObjectIdentifier secp112r1 = ellipticCurve.branch("6");
    /**  secp112r2 OID: 1.3.132.0.7 */
    static final ASN1ObjectIdentifier secp112r2 = ellipticCurve.branch("7");
    /**  secp160r1 OID: 1.3.132.0.8 */
    static final ASN1ObjectIdentifier secp160r1 = ellipticCurve.branch("8");
    /**  secp160k1 OID: 1.3.132.0.9 */
    static final ASN1ObjectIdentifier secp160k1 = ellipticCurve.branch("9");
    /**  secp256k1 OID: 1.3.132.0.10 */
    static final ASN1ObjectIdentifier secp256k1 = ellipticCurve.branch("10");
    /**  sect163r2 OID: 1.3.132.0.15 */
    static final ASN1ObjectIdentifier sect163r2 = ellipticCurve.branch("15");
    /**  sect283k1 OID: 1.3.132.0.16 */
    static final ASN1ObjectIdentifier sect283k1 = ellipticCurve.branch("16");
    /**  sect283r1 OID: 1.3.132.0.17 */
    static final ASN1ObjectIdentifier sect283r1 = ellipticCurve.branch("17");
    /**  sect131r1 OID: 1.3.132.0.22 */
    static final ASN1ObjectIdentifier sect131r1 = ellipticCurve.branch("22");
    /**  sect131r2 OID: 1.3.132.0.23 */
    static final ASN1ObjectIdentifier sect131r2 = ellipticCurve.branch("23");
    /**  sect193r1 OID: 1.3.132.0.24 */
    static final ASN1ObjectIdentifier sect193r1 = ellipticCurve.branch("24");
    /**  sect193r2 OID: 1.3.132.0.25 */
    static final ASN1ObjectIdentifier sect193r2 = ellipticCurve.branch("25");
    /**  sect233k1 OID: 1.3.132.0.26 */
    static final ASN1ObjectIdentifier sect233k1 = ellipticCurve.branch("26");
    /**  sect233r1 OID: 1.3.132.0.27 */
    static final ASN1ObjectIdentifier sect233r1 = ellipticCurve.branch("27");
    /**  secp128r1 OID: 1.3.132.0.28 */
    static final ASN1ObjectIdentifier secp128r1 = ellipticCurve.branch("28");
    /**  secp128r2 OID: 1.3.132.0.29 */
    static final ASN1ObjectIdentifier secp128r2 = ellipticCurve.branch("29");
    /**  secp160r2 OID: 1.3.132.0.30 */
    static final ASN1ObjectIdentifier secp160r2 = ellipticCurve.branch("30");
    /**  secp192k1 OID: 1.3.132.0.31 */
    static final ASN1ObjectIdentifier secp192k1 = ellipticCurve.branch("31");
    /**  secp224k1 OID: 1.3.132.0.32 */
    static final ASN1ObjectIdentifier secp224k1 = ellipticCurve.branch("32");
    /**  secp224r1 OID: 1.3.132.0.33 */
    static final ASN1ObjectIdentifier secp224r1 = ellipticCurve.branch("33");
    /**  secp384r1 OID: 1.3.132.0.34 */
    static final ASN1ObjectIdentifier secp384r1 = ellipticCurve.branch("34");
    /**  secp521r1 OID: 1.3.132.0.35 */
    static final ASN1ObjectIdentifier secp521r1 = ellipticCurve.branch("35");
    /**  sect409k1 OID: 1.3.132.0.36 */
    static final ASN1ObjectIdentifier sect409k1 = ellipticCurve.branch("36");
    /**  sect409r1 OID: 1.3.132.0.37 */
    static final ASN1ObjectIdentifier sect409r1 = ellipticCurve.branch("37");
    /**  sect571k1 OID: 1.3.132.0.38 */
    static final ASN1ObjectIdentifier sect571k1 = ellipticCurve.branch("38");
    /**  sect571r1 OID: 1.3.132.0.39 */
    static final ASN1ObjectIdentifier sect571r1 = ellipticCurve.branch("39");

    /**  secp192r1 OID: 1.3.132.0.prime192v1 */
    static final ASN1ObjectIdentifier secp192r1 = X9ObjectIdentifiers.prime192v1;
    /**  secp256r1 OID: 1.3.132.0.prime256v1 */
    static final ASN1ObjectIdentifier secp256r1 = X9ObjectIdentifiers.prime256v1;

}
