package org.bouncycastle.asn1.esf;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AttributeCertificate;


public class SignerAttribute
    extends ASN1Object
{
    private Object[] values;

    public static SignerAttribute getInstance(
        Object o)
    {
        if (o instanceof SignerAttribute)
        {
            return (SignerAttribute) o;
        }
        else if (o != null)
        {
            return new SignerAttribute(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private SignerAttribute(
        ASN1Sequence seq)
    {
        int index = 0;
        values = new Object[seq.size()];

        for (Enumeration e = seq.getObjects(); e.hasMoreElements();)
        {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(e.nextElement());

            if (taggedObject.getTagNo() == 0)
            {
                ASN1Sequence attrs = ASN1Sequence.getInstance(taggedObject, true);
                Attribute[]  attributes = new Attribute[attrs.size()];

                for (int i = 0; i != attributes.length; i++)
                {
                    attributes[i] = Attribute.getInstance(attrs.getObjectAt(i));
                }
                values[index] = attributes;
            }
            else if (taggedObject.getTagNo() == 1)
            {
                values[index] = AttributeCertificate.getInstance(ASN1Sequence.getInstance(taggedObject, true));
            }
            else
            {
                throw new IllegalArgumentException("illegal tag: " + taggedObject.getTagNo());
            }
            index++;
        }
    }

    public SignerAttribute(
        Attribute[] claimedAttributes)
    {
        this.values = new Object[1];
        this.values[0] = claimedAttributes;
    }

    public SignerAttribute(
        AttributeCertificate certifiedAttributes)
    {
        this.values = new Object[1];
        this.values[0] = certifiedAttributes;
    }

    /**
     * Return the sequence of choices - the array elements will either be of
     * type Attribute[] or AttributeCertificate depending on what tag was used.
     *
     * @return array of choices.
     */
    public Object[] getValues()
    {
        return values;
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
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != values.length; i++)
        {
            if (values[i] instanceof Attribute[])
            {
                v.add(new DERTaggedObject(0, new DERSequence((Attribute[])values[i])));
            }
            else
            {
                v.add(new DERTaggedObject(1, (AttributeCertificate)values[i]));
            }
        }

        return new DERSequence(v);
    }
}
