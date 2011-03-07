package com.google.bitcoin.bouncycastle.asn1.esf;

import com.google.bitcoin.bouncycastle.asn1.*;
import com.google.bitcoin.bouncycastle.asn1.x509.AttributeCertificate;


public class SignerAttribute
    extends ASN1Encodable
{
    private ASN1Sequence          claimedAttributes;
    private AttributeCertificate  certifiedAttributes;

    public static SignerAttribute getInstance(
        Object o)
    {
        if (o == null || o instanceof SignerAttribute)
        {
            return (SignerAttribute) o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new SignerAttribute(o);
        }

        throw new IllegalArgumentException(
                "unknown object in 'SignerAttribute' factory: "
                        + o.getClass().getName() + ".");
    }

    private SignerAttribute(
        Object o)
    {
        ASN1Sequence seq = (ASN1Sequence) o;
        DERTaggedObject taggedObject = (DERTaggedObject) seq.getObjectAt(0);
        if (taggedObject.getTagNo() == 0)
        {
            claimedAttributes = ASN1Sequence.getInstance(taggedObject, true);
        }
        else if (taggedObject.getTagNo() == 1)
        {
            certifiedAttributes = AttributeCertificate.getInstance(taggedObject);
        }
        else
        {
            throw new IllegalArgumentException("illegal tag.");
        }
    }

    public SignerAttribute(
        ASN1Sequence claimedAttributes)
    {
        this.claimedAttributes = claimedAttributes;
    }

    public SignerAttribute(
        AttributeCertificate certifiedAttributes)
    {
        this.certifiedAttributes = certifiedAttributes;
    }

    public ASN1Sequence getClaimedAttributes()
    {
        return claimedAttributes;
    }

    public AttributeCertificate getCertifiedAttributes()
    {
        return certifiedAttributes;
    }

    /**
     *
     * <pre>
     *  SignerAttribute ::= SEQUENCE OF CHOICE {
     *      claimedAttributes   [0] ClaimedAttributes,
     *      certifiedAttributes [1] CertifiedAttributes }
     *
     *  ClaimedAttributes ::= SEQUENCE OF Attribute
     *  CertifiedAttributes ::= AttributeCertificate -- as defined in RFC 3281: see clause 4.1.
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (claimedAttributes != null)
        {
            v.add(new DERTaggedObject(0, claimedAttributes));
        }
        else
        {
            v.add(new DERTaggedObject(1, certifiedAttributes));
        }

        return new DERSequence(v);
    }
}
