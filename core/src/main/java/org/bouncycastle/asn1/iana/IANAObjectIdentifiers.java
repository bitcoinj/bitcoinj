package org.bouncycastle.asn1.iana;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * IANA:
 *  { iso(1) identifier-organization(3) dod(6) internet(1) } == IETF defined things
 */
public interface IANAObjectIdentifiers
{

    /** { iso(1) identifier-organization(3) dod(6) internet(1) } == IETF defined things */
    static final ASN1ObjectIdentifier   internet       = new ASN1ObjectIdentifier("1.3.6.1");
    /** 1.3.6.1.1: Internet directory: X.500 */
    static final ASN1ObjectIdentifier   directory      = internet.branch("1");
    /** 1.3.6.1.2: Internet management */
    static final ASN1ObjectIdentifier   mgmt           = internet.branch("2");
    /** 1.3.6.1.3: */
    static final ASN1ObjectIdentifier   experimental   = internet.branch("3");
    /** 1.3.6.1.4: */
    static final ASN1ObjectIdentifier   _private       = internet.branch("4");
    /** 1.3.6.1.5: Security services */
    static final ASN1ObjectIdentifier   security       = internet.branch("5");
    /** 1.3.6.1.6: SNMPv2 -- never really used */
    static final ASN1ObjectIdentifier   SNMPv2         = internet.branch("6");
    /** 1.3.6.1.7: mail -- never really used */
    static final ASN1ObjectIdentifier   mail           = internet.branch("7");


    // id-SHA1 OBJECT IDENTIFIER ::=    
    // {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) ipsec(8) isakmpOakley(1)}
    //


    /** IANA security mechanisms; 1.3.6.1.5.5 */
    static final ASN1ObjectIdentifier    security_mechanisms  = security.branch("5");
    /** IANA security nametypes;  1.3.6.1.5.6 */
    static final ASN1ObjectIdentifier    security_nametypes   = security.branch("6");

    /** PKIX base OID:            1.3.6.1.5.6.6 */
    static final ASN1ObjectIdentifier    pkix                 = security_mechanisms.branch("6");


    /** IPSEC base OID:                        1.3.6.1.5.5.8 */
    static final ASN1ObjectIdentifier    ipsec                = security_mechanisms.branch("8");
    /** IPSEC ISAKMP-Oakley OID:               1.3.6.1.5.5.8.1 */
    static final ASN1ObjectIdentifier    isakmpOakley         = ipsec.branch("1");

    /** IPSEC ISAKMP-Oakley hmacMD5 OID:       1.3.6.1.5.5.8.1.1 */
    static final ASN1ObjectIdentifier    hmacMD5              = isakmpOakley.branch("1");
    /** IPSEC ISAKMP-Oakley hmacSHA1 OID:      1.3.6.1.5.5.8.1.2 */
    static final ASN1ObjectIdentifier    hmacSHA1             = isakmpOakley.branch("2");
    
    /** IPSEC ISAKMP-Oakley hmacTIGER OID:     1.3.6.1.5.5.8.1.3 */
    static final ASN1ObjectIdentifier    hmacTIGER            = isakmpOakley.branch("3");
    
    /** IPSEC ISAKMP-Oakley hmacRIPEMD160 OID: 1.3.6.1.5.5.8.1.4 */
    static final ASN1ObjectIdentifier    hmacRIPEMD160        = isakmpOakley.branch("4");

}
