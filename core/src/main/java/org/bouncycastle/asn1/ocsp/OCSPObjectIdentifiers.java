package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * OIDs for <a href="http://tools.ietf.org/html/rfc2560">RFC 2560</a>
 * Online Certificate Status Protocol - OCSP.
 */
public interface OCSPObjectIdentifiers
{
    /** OID: 1.3.6.1.5.5.7.48.1 */
    static final ASN1ObjectIdentifier id_pkix_ocsp       = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1");
    /** OID: 1.3.6.1.5.5.7.48.1.1 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_basic = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1");
    
    /** OID: 1.3.6.1.5.5.7.48.1.2 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_nonce = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2");
    /** OID: 1.3.6.1.5.5.7.48.1.3 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_crl   = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.3");
    
    /** OID: 1.3.6.1.5.5.7.48.1.4 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_response        = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.4");
    /** OID: 1.3.6.1.5.5.7.48.1.5 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_nocheck         = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5");
    /** OID: 1.3.6.1.5.5.7.48.1.6 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_archive_cutoff  = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.6");
    /** OID: 1.3.6.1.5.5.7.48.1.7 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_service_locator = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.7");
}
