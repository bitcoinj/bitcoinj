package org.bouncycastle.asn1.eac;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * German Federal Office for Information Security
 * (Bundesamt für Sicherheit in der Informationstechnik)
 * <a href="http://www.bsi.bund.de/">http://www.bsi.bund.de/</a>
 * <p>
 * <a href="https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03110/BSITR03110.html">BSI TR-03110</a>
 * Technical Guideline Advanced Security Mechanisms for Machine Readable Travel Documents
 * <p>
 * <a href="https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03110/TR-03110_v2.1_P3pdf.pdf?__blob=publicationFile">Technical Guideline TR-03110-3</a>
 * Advanced Security Mechanisms for Machine Readable Travel Documents;
 * Part 3: Common Specifications.
 */

public interface EACObjectIdentifiers
{
    /**
     * <pre>
     * bsi-de OBJECT IDENTIFIER ::= {
     *     itu-t(0) identified-organization(4) etsi(0)
     *     reserved(127) etsi-identified-organization(0) 7
     * }
     * </pre>
     * OID: 0.4.0.127.0.7
     */
    static final ASN1ObjectIdentifier    bsi_de      = new ASN1ObjectIdentifier("0.4.0.127.0.7");

    /**
     * <pre>
     * id-PK OBJECT IDENTIFIER ::= {
     *     bsi-de protocols(2) smartcard(2) 1
     * }
     * </pre>
     * OID: 0.4.0.127.0.7.2.2.1
     */
    static final ASN1ObjectIdentifier    id_PK      = bsi_de.branch("2.2.1");

    /** OID: 0.4.0.127.0.7.2.2.1.1 */
    static final ASN1ObjectIdentifier    id_PK_DH   = id_PK.branch("1");
    /** OID: 0.4.0.127.0.7.2.2.1.2 */
    static final ASN1ObjectIdentifier    id_PK_ECDH = id_PK.branch("2");

    /**
     * <pre>
     * id-CA OBJECT IDENTIFIER ::= {
     *     bsi-de protocols(2) smartcard(2) 3
     * }
     * </pre>
     * OID: 0.4.0.127.0.7.2.2.3
     */
    static final ASN1ObjectIdentifier    id_CA                   = bsi_de.branch("2.2.3");
    /** OID: 0.4.0.127.0.7.2.2.3.1 */
    static final ASN1ObjectIdentifier    id_CA_DH                = id_CA.branch("1");
    /** OID: 0.4.0.127.0.7.2.2.3.1.1 */
    static final ASN1ObjectIdentifier    id_CA_DH_3DES_CBC_CBC   = id_CA_DH.branch("1");
    /** OID: 0.4.0.127.0.7.2.2.3.2 */
    static final ASN1ObjectIdentifier    id_CA_ECDH              = id_CA.branch("2");
    /** OID: 0.4.0.127.0.7.2.2.3.2.1 */
    static final ASN1ObjectIdentifier    id_CA_ECDH_3DES_CBC_CBC = id_CA_ECDH.branch("1");

    /**
     * <pre>
     * id-TA OBJECT IDENTIFIER ::= {
     *     bsi-de protocols(2) smartcard(2) 2
     * }
     * </pre>
     * OID: 0.4.0.127.0.7.2.2.2
     */
    static final ASN1ObjectIdentifier    id_TA = bsi_de.branch("2.2.2");

    /** OID: 0.4.0.127.0.7.2.2.2.1 */
    static final ASN1ObjectIdentifier    id_TA_RSA              = id_TA.branch("1");
    /** OID: 0.4.0.127.0.7.2.2.2.1.1 */
    static final ASN1ObjectIdentifier    id_TA_RSA_v1_5_SHA_1   = id_TA_RSA.branch("1");
    /** OID: 0.4.0.127.0.7.2.2.2.1.2 */
    static final ASN1ObjectIdentifier    id_TA_RSA_v1_5_SHA_256 = id_TA_RSA.branch("2");
    /** OID: 0.4.0.127.0.7.2.2.2.1.3 */
    static final ASN1ObjectIdentifier    id_TA_RSA_PSS_SHA_1    = id_TA_RSA.branch("3");
    /** OID: 0.4.0.127.0.7.2.2.2.1.4 */
    static final ASN1ObjectIdentifier    id_TA_RSA_PSS_SHA_256  = id_TA_RSA.branch("4");
    /** OID: 0.4.0.127.0.7.2.2.2.1.5 */
    static final ASN1ObjectIdentifier    id_TA_RSA_v1_5_SHA_512 = id_TA_RSA.branch("5");
    /** OID: 0.4.0.127.0.7.2.2.2.1.6 */
    static final ASN1ObjectIdentifier    id_TA_RSA_PSS_SHA_512  = id_TA_RSA.branch("6");
    /** OID: 0.4.0.127.0.7.2.2.2.2 */
    static final ASN1ObjectIdentifier    id_TA_ECDSA            = id_TA.branch("2");
    /** OID: 0.4.0.127.0.7.2.2.2.2.1 */
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_1      = id_TA_ECDSA.branch("1");
    /** OID: 0.4.0.127.0.7.2.2.2.2.2 */
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_224    = id_TA_ECDSA.branch("2");
    /** OID: 0.4.0.127.0.7.2.2.2.2.3 */
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_256    = id_TA_ECDSA.branch("3");
    /** OID: 0.4.0.127.0.7.2.2.2.2.4 */
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_384    = id_TA_ECDSA.branch("4");
    /** OID: 0.4.0.127.0.7.2.2.2.2.5 */
    static final ASN1ObjectIdentifier    id_TA_ECDSA_SHA_512    = id_TA_ECDSA.branch("5");

    /**
     * <pre>
     * id-EAC-ePassport OBJECT IDENTIFIER ::= {
     *     bsi-de applications(3) mrtd(1) roles(2) 1
     * }
     * </pre>
     * OID: 0.4.0.127.0.7.3.1.2.1
     */
    static final ASN1ObjectIdentifier id_EAC_ePassport = bsi_de.branch("3.1.2.1");
}
