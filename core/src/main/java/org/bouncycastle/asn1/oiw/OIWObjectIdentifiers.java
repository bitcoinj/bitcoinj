package org.bouncycastle.asn1.oiw;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * OIW organization's OIDs:
 * <p>
 * id-SHA1 OBJECT IDENTIFIER ::=    
 *   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }
 */
public interface OIWObjectIdentifiers
{
    /** OID: 1.3.14.3.2.2 */
    static final ASN1ObjectIdentifier    md4WithRSA              = new ASN1ObjectIdentifier("1.3.14.3.2.2");
    /** OID: 1.3.14.3.2.3 */
    static final ASN1ObjectIdentifier    md5WithRSA              = new ASN1ObjectIdentifier("1.3.14.3.2.3");
    /** OID: 1.3.14.3.2.4 */
    static final ASN1ObjectIdentifier    md4WithRSAEncryption    = new ASN1ObjectIdentifier("1.3.14.3.2.4");
    
    /** OID: 1.3.14.3.2.6 */
    static final ASN1ObjectIdentifier    desECB                  = new ASN1ObjectIdentifier("1.3.14.3.2.6");
    /** OID: 1.3.14.3.2.7 */
    static final ASN1ObjectIdentifier    desCBC                  = new ASN1ObjectIdentifier("1.3.14.3.2.7");
    /** OID: 1.3.14.3.2.8 */
    static final ASN1ObjectIdentifier    desOFB                  = new ASN1ObjectIdentifier("1.3.14.3.2.8");
    /** OID: 1.3.14.3.2.9 */
    static final ASN1ObjectIdentifier    desCFB                  = new ASN1ObjectIdentifier("1.3.14.3.2.9");

    /** OID: 1.3.14.3.2.17 */
    static final ASN1ObjectIdentifier    desEDE                  = new ASN1ObjectIdentifier("1.3.14.3.2.17");
    
    /** OID: 1.3.14.3.2.26 */
    static final ASN1ObjectIdentifier    idSHA1                  = new ASN1ObjectIdentifier("1.3.14.3.2.26");

    /** OID: 1.3.14.3.2.27 */
    static final ASN1ObjectIdentifier    dsaWithSHA1             = new ASN1ObjectIdentifier("1.3.14.3.2.27");

    /** OID: 1.3.14.3.2.29 */
    static final ASN1ObjectIdentifier    sha1WithRSA             = new ASN1ObjectIdentifier("1.3.14.3.2.29");
    
    /**
     * <pre>
     * ElGamal Algorithm OBJECT IDENTIFIER ::=    
     *   {iso(1) identified-organization(3) oiw(14) dirservsig(7) algorithm(2) encryption(1) 1 }
     * </pre>
     * OID: 1.3.14.7.2.1.1
     */
    static final ASN1ObjectIdentifier    elGamalAlgorithm        = new ASN1ObjectIdentifier("1.3.14.7.2.1.1");

}
