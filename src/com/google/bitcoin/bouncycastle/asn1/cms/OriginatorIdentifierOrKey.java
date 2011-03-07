package com.google.bitcoin.bouncycastle.asn1.cms;

import com.google.bitcoin.bouncycastle.asn1.ASN1Choice;
import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1OctetString;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DEREncodable;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;
import com.google.bitcoin.bouncycastle.asn1.x509.SubjectKeyIdentifier;

public class OriginatorIdentifierOrKey
    extends ASN1Encodable
    implements ASN1Choice
{
    private DEREncodable id;

    public OriginatorIdentifierOrKey(
        IssuerAndSerialNumber id)
    {
        this.id = id;
    }

    /**
     * @deprecated use version taking a SubjectKeyIdentifier
     */
    public OriginatorIdentifierOrKey(
        ASN1OctetString id)
    {
        this(new SubjectKeyIdentifier(id));
    }

    public OriginatorIdentifierOrKey(
        SubjectKeyIdentifier id)
    {
        this.id = new DERTaggedObject(false, 0, id);
    }

    public OriginatorIdentifierOrKey(
        OriginatorPublicKey id)
    {
        this.id = new DERTaggedObject(false, 1, id);
    }

    /**
     * @deprecated use more specific version
     */
    public OriginatorIdentifierOrKey(
        DERObject id)
    {
        this.id = id;
    }

    /**
     * return an OriginatorIdentifierOrKey object from a tagged object.
     *
     * @param o the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static OriginatorIdentifierOrKey getInstance(
        ASN1TaggedObject    o,
        boolean             explicit)
    {
        if (!explicit)
        {
            throw new IllegalArgumentException(
                    "Can't implicitly tag OriginatorIdentifierOrKey");
        }

        return getInstance(o.getObject());
    }
    
    /**
     * return an OriginatorIdentifierOrKey object from the given object.
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static OriginatorIdentifierOrKey getInstance(
        Object o)
    {
        if (o == null || o instanceof OriginatorIdentifierOrKey)
        {
            return (OriginatorIdentifierOrKey)o;
        }

        if (o instanceof IssuerAndSerialNumber)
        {
            return new OriginatorIdentifierOrKey((IssuerAndSerialNumber)o);
        }

        if (o instanceof SubjectKeyIdentifier)
        {
            return new OriginatorIdentifierOrKey((SubjectKeyIdentifier)o);
        }

        if (o instanceof OriginatorPublicKey)
        {
            return new OriginatorIdentifierOrKey((OriginatorPublicKey)o);
        }

        if (o instanceof ASN1TaggedObject)
        {
            // TODO Add validation
            return new OriginatorIdentifierOrKey((ASN1TaggedObject)o);
        }

        throw new IllegalArgumentException("Invalid OriginatorIdentifierOrKey: " + o.getClass().getName());
    }

    public DEREncodable getId()
    {
        return id;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber()
    {
        if (id instanceof IssuerAndSerialNumber)
        {
            return (IssuerAndSerialNumber)id;
        }

        return null;
    }

    public SubjectKeyIdentifier getSubjectKeyIdentifier()
    {
        if (id instanceof ASN1TaggedObject && ((ASN1TaggedObject)id).getTagNo() == 0)
        {
            return SubjectKeyIdentifier.getInstance((ASN1TaggedObject)id, false);
        }

        return null;
    }

    public OriginatorPublicKey getOriginatorKey()
    {
        if (id instanceof ASN1TaggedObject && ((ASN1TaggedObject)id).getTagNo() == 1)
        {
            return OriginatorPublicKey.getInstance((ASN1TaggedObject)id, false);
        }

        return null;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * OriginatorIdentifierOrKey ::= CHOICE {
     *     issuerAndSerialNumber IssuerAndSerialNumber,
     *     subjectKeyIdentifier [0] SubjectKeyIdentifier,
     *     originatorKey [1] OriginatorPublicKey 
     * }
     *
     * SubjectKeyIdentifier ::= OCTET STRING
     * </pre>
     */
    public DERObject toASN1Object()
    {
        return id.getDERObject();
    }
}
