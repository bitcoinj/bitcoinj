package org.bouncycastle.asn1.microsoft;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Microsoft
 * <p>
 * Object identifier base:
 * <pre>
 *    iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) microsoft(311)
 * </pre>
 * 1.3.6.1.4.1.311
 */
public interface MicrosoftObjectIdentifiers
{
    /** Base OID: 1.3.6.1.4.1.311 */
    static final ASN1ObjectIdentifier    microsoft               = new ASN1ObjectIdentifier("1.3.6.1.4.1.311");
    /** OID: 1.3.6.1.4.1.311.20.2 */
    static final ASN1ObjectIdentifier    microsoftCertTemplateV1 = microsoft.branch("20.2");
    /** OID: 1.3.6.1.4.1.311.21.1 */
    static final ASN1ObjectIdentifier    microsoftCaVersion      = microsoft.branch("21.1");
    /** OID: 1.3.6.1.4.1.311.21.2 */
    static final ASN1ObjectIdentifier    microsoftPrevCaCertHash = microsoft.branch("21.2");
    /** OID: 1.3.6.1.4.1.311.21.7 */
    static final ASN1ObjectIdentifier    microsoftCertTemplateV2 = microsoft.branch("21.7");
    /** OID: 1.3.6.1.4.1.311.21.10 */
    static final ASN1ObjectIdentifier    microsoftAppPolicies    = microsoft.branch("21.10");
}
