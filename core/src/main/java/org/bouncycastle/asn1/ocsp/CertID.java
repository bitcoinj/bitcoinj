package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class CertID
    extends ASN1Object
{
    AlgorithmIdentifier    hashAlgorithm;
    ASN1OctetString        issuerNameHash;
    ASN1OctetString        issuerKeyHash;
    ASN1Integer             serialNumber;

    public CertID(
        AlgorithmIdentifier hashAlgorithm,
        ASN1OctetString     issuerNameHash,
        ASN1OctetString     issuerKeyHash,
        ASN1Integer         serialNumber)
    {
        this.hashAlgorithm = hashAlgorithm;
        this.issuerNameHash = issuerNameHash;
        this.issuerKeyHash = issuerKeyHash;
        this.serialNumber = serialNumber;
    }

    private CertID(
        ASN1Sequence    seq)
    {
        hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        issuerNameHash = (ASN1OctetString)seq.getObjectAt(1);
        issuerKeyHash = (ASN1OctetString)seq.getObjectAt(2);
        serialNumber = (ASN1Integer)seq.getObjectAt(3);
    }

    public static CertID getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertID getInstance(
        Object  obj)
    {
        if (obj instanceof CertID)
        {
            return (CertID)obj;
        }
        else if (obj != null)
        {
            return new CertID(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    public ASN1OctetString getIssuerNameHash()
    {
        return issuerNameHash;
    }

    public ASN1OctetString getIssuerKeyHash()
    {
        return issuerKeyHash;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * CertID          ::=     SEQUENCE {
     *     hashAlgorithm       AlgorithmIdentifier,
     *     issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
     *     issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
     *     serialNumber        CertificateSerialNumber }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(hashAlgorithm);
        v.add(issuerNameHash);
        v.add(issuerKeyHash);
        v.add(serialNumber);

        return new DERSequence(v);
    }
}
