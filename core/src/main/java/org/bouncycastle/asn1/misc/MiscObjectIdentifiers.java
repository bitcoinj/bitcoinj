package org.bouncycastle.asn1.misc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface MiscObjectIdentifiers
{
    //
    // Netscape
    //       iso/itu(2) joint-assign(16) us(840) uscompany(1) netscape(113730) cert-extensions(1) }
    //
    /** Netscape cert extensions OID base: 2.16.840.1.113730.1  */
    static final ASN1ObjectIdentifier    netscape                = new ASN1ObjectIdentifier("2.16.840.1.113730.1");
    /** Netscape cert CertType OID: 2.16.840.1.113730.1.1  */
    static final ASN1ObjectIdentifier    netscapeCertType        = netscape.branch("1");
    /** Netscape cert BaseURL OID: 2.16.840.1.113730.1.2  */
    static final ASN1ObjectIdentifier    netscapeBaseURL         = netscape.branch("2");
    /** Netscape cert RevocationURL OID: 2.16.840.1.113730.1.3  */
    static final ASN1ObjectIdentifier    netscapeRevocationURL   = netscape.branch("3");
    /** Netscape cert CARevocationURL OID: 2.16.840.1.113730.1.4  */
    static final ASN1ObjectIdentifier    netscapeCARevocationURL = netscape.branch("4");
    /** Netscape cert RenewalURL OID: 2.16.840.1.113730.1.7  */
    static final ASN1ObjectIdentifier    netscapeRenewalURL      = netscape.branch("7");
    /** Netscape cert CApolicyURL OID: 2.16.840.1.113730.1.8  */
    static final ASN1ObjectIdentifier    netscapeCApolicyURL     = netscape.branch("8");
    /** Netscape cert SSLServerName OID: 2.16.840.1.113730.1.12  */
    static final ASN1ObjectIdentifier    netscapeSSLServerName   = netscape.branch("12");
    /** Netscape cert CertComment OID: 2.16.840.1.113730.1.13  */
    static final ASN1ObjectIdentifier    netscapeCertComment     = netscape.branch("13");
    
    //
    // Verisign
    //       iso/itu(2) joint-assign(16) us(840) uscompany(1) verisign(113733) cert-extensions(1) }
    //
    /** Verisign OID base: 2.16.840.1.113733.1 */
    static final ASN1ObjectIdentifier   verisign                = new ASN1ObjectIdentifier("2.16.840.1.113733.1");

    /** Verisign CZAG (Country,Zip,Age,Gender) Extension OID: 2.16.840.1.113733.1.6.3 */
    static final ASN1ObjectIdentifier    verisignCzagExtension   = verisign.branch("6.3");
    /** Verisign D&amp;B D-U-N-S number Extension OID: 2.16.840.1.113733.1.6.15 */
    static final ASN1ObjectIdentifier    verisignDnbDunsNumber   = verisign.branch("6.15");

    //
    // Novell
    //       iso/itu(2) country(16) us(840) organization(1) novell(113719)
    //
    /** Novell OID base: 2.16.840.1.113719 */
    static final ASN1ObjectIdentifier    novell                  = new ASN1ObjectIdentifier("2.16.840.1.113719");
    /** Novell SecurityAttribs OID: 2.16.840.1.113719.1.9.4.1 */
    static final ASN1ObjectIdentifier    novellSecurityAttribs   = novell.branch("1.9.4.1");

    //
    // Entrust
    //       iso(1) member-body(16) us(840) nortelnetworks(113533) entrust(7)
    //
    /** NortelNetworks Entrust OID base: 1.2.840.113533.7 */
    static final ASN1ObjectIdentifier    entrust                 = new ASN1ObjectIdentifier("1.2.840.113533.7");
    /** NortelNetworks Entrust VersionExtension OID: 1.2.840.113533.7.65.0 */
    static final ASN1ObjectIdentifier    entrustVersionExtension = entrust.branch("65.0");
}
