package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public interface CMSObjectIdentifiers
{
    /** PKCS#7: 1.2.840.113549.1.7.1 */
    static final ASN1ObjectIdentifier    data = PKCSObjectIdentifiers.data;
    /** PKCS#7: 1.2.840.113549.1.7.2 */
    static final ASN1ObjectIdentifier    signedData = PKCSObjectIdentifiers.signedData;
    /** PKCS#7: 1.2.840.113549.1.7.3 */
    static final ASN1ObjectIdentifier    envelopedData = PKCSObjectIdentifiers.envelopedData;
    /** PKCS#7: 1.2.840.113549.1.7.4 */
    static final ASN1ObjectIdentifier    signedAndEnvelopedData = PKCSObjectIdentifiers.signedAndEnvelopedData;
    /** PKCS#7: 1.2.840.113549.1.7.5 */
    static final ASN1ObjectIdentifier    digestedData = PKCSObjectIdentifiers.digestedData;
    /** PKCS#7: 1.2.840.113549.1.7.6 */
    static final ASN1ObjectIdentifier    encryptedData = PKCSObjectIdentifiers.encryptedData;
    /** PKCS#9: 1.2.840.113549.1.9.16.1.2 -- smime ct authData */
    static final ASN1ObjectIdentifier    authenticatedData = PKCSObjectIdentifiers.id_ct_authData;
    /** PKCS#9: 1.2.840.113549.1.9.16.1.9 -- smime ct compressedData */
    static final ASN1ObjectIdentifier    compressedData = PKCSObjectIdentifiers.id_ct_compressedData;
    /** PKCS#9: 1.2.840.113549.1.9.16.1.23 -- smime ct authEnvelopedData */
    static final ASN1ObjectIdentifier    authEnvelopedData = PKCSObjectIdentifiers.id_ct_authEnvelopedData;
    /** PKCS#9: 1.2.840.113549.1.9.16.1.31 -- smime ct timestampedData*/
    static final ASN1ObjectIdentifier    timestampedData = PKCSObjectIdentifiers.id_ct_timestampedData;

    /**
     * The other Revocation Info arc
     * <p>
     * <pre>
     * id-ri OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
     *        dod(6) internet(1) security(5) mechanisms(5) pkix(7) ri(16) }
     * </pre>
     */
    static final ASN1ObjectIdentifier    id_ri = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.16");

    /** 1.3.6.1.5.5.7.16.2 */
    static final ASN1ObjectIdentifier    id_ri_ocsp_response = id_ri.branch("2");
    /** 1.3.6.1.5.5.7.16.4 */
    static final ASN1ObjectIdentifier    id_ri_scvp = id_ri.branch("4");
}
