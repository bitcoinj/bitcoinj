package com.google.bitcoin.bouncycastle.asn1.ess;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1OctetString;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.google.bitcoin.bouncycastle.asn1.x509.DigestInfo;
import com.google.bitcoin.bouncycastle.asn1.x509.IssuerSerial;

public class OtherCertID
    extends ASN1Encodable
{
    private ASN1Encodable otherCertHash;
    private IssuerSerial issuerSerial;

    public static OtherCertID getInstance(Object o)
    {
        if (o == null || o instanceof OtherCertID)
        {
            return (OtherCertID) o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new OtherCertID((ASN1Sequence) o);
        }

        throw new IllegalArgumentException(
                "unknown object in 'OtherCertID' factory : "
                        + o.getClass().getName() + ".");
    }

    /**
     * constructor
     */
    public OtherCertID(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        if (seq.getObjectAt(0).getDERObject() instanceof ASN1OctetString)
        {
            otherCertHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        }
        else
        {
            otherCertHash = DigestInfo.getInstance(seq.getObjectAt(0));

        }

        if (seq.size() > 1)
        {
            issuerSerial = new IssuerSerial(ASN1Sequence.getInstance(seq.getObjectAt(1)));
        }
    }

    public OtherCertID(
        AlgorithmIdentifier  algId,
        byte[]               digest)
    {
        this.otherCertHash = new DigestInfo(algId, digest);
    }

    public OtherCertID(
        AlgorithmIdentifier  algId,
        byte[]               digest,
        IssuerSerial    issuerSerial)
    {
        this.otherCertHash = new DigestInfo(algId, digest);
        this.issuerSerial = issuerSerial;
    }

    public AlgorithmIdentifier getAlgorithmHash()
    {
        if (otherCertHash.getDERObject() instanceof ASN1OctetString)
        {
            // SHA-1
            return new AlgorithmIdentifier("1.3.14.3.2.26");
        }
        else
        {
            return DigestInfo.getInstance(otherCertHash).getAlgorithmId();
        }
    }

    public byte[] getCertHash()
    {
        if (otherCertHash.getDERObject() instanceof ASN1OctetString)
        {
            // SHA-1
            return ((ASN1OctetString)otherCertHash.getDERObject()).getOctets();
        }
        else
        {
            return DigestInfo.getInstance(otherCertHash).getDigest();
        }
    }

    public IssuerSerial getIssuerSerial()
    {
        return issuerSerial;
    }

    /**
     * <pre>
     * OtherCertID ::= SEQUENCE {
     *     otherCertHash    OtherHash,
     *     issuerSerial     IssuerSerial OPTIONAL }
     *
     * OtherHash ::= CHOICE {
     *     sha1Hash     OCTET STRING,
     *     otherHash    OtherHashAlgAndValue }
     *
     * OtherHashAlgAndValue ::= SEQUENCE {
     *     hashAlgorithm    AlgorithmIdentifier,
     *     hashValue        OCTET STRING }
     *
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(otherCertHash);

        if (issuerSerial != null)
        {
            v.add(issuerSerial);
        }

        return new DERSequence(v);
    }
}
