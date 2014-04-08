package org.bouncycastle.asn1.x509.sigi;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Object Identifiers of SigI specifciation (German Signature Law
 * Interoperability specification).
 */
public interface SigIObjectIdentifiers
{
    /**
     * OID: 1.3.36.8
     */
    public final static ASN1ObjectIdentifier id_sigi = new ASN1ObjectIdentifier("1.3.36.8");

    /**
     * Key purpose IDs for German SigI (Signature Interoperability
     * Specification)
     * <p>
     * OID: 1.3.36.8.2
     */
    public final static ASN1ObjectIdentifier id_sigi_kp = new ASN1ObjectIdentifier("1.3.36.8.2");

    /**
     * Certificate policy IDs for German SigI (Signature Interoperability
     * Specification)
     * <p>
     * OID: 1.3.36.8.1
     */
    public final static ASN1ObjectIdentifier id_sigi_cp = new ASN1ObjectIdentifier("1.3.36.8.1");

    /**
     * Other Name IDs for German SigI (Signature Interoperability Specification)
     * <p>
     * OID: 1.3.36.8.4
     */
    public final static ASN1ObjectIdentifier id_sigi_on = new ASN1ObjectIdentifier("1.3.36.8.4");

    /**
     * To be used for for the generation of directory service certificates.
     * <p>
     * OID: 1.3.36.8.2.1
     */
    public static final ASN1ObjectIdentifier id_sigi_kp_directoryService = new ASN1ObjectIdentifier("1.3.36.8.2.1");

    /**
     * ID for PersonalData
     * <p>
     * OID: 1.3.36.8.4.1
     */
    public static final ASN1ObjectIdentifier id_sigi_on_personalData = new ASN1ObjectIdentifier("1.3.36.8.4.1");

    /**
     * Certificate is conformant to german signature law.
     * <p>
     * OID: 1.3.36.8.1.1
     */
    public static final ASN1ObjectIdentifier id_sigi_cp_sigconform = new ASN1ObjectIdentifier("1.3.36.8.1.1");

}
