package org.bouncycastle.asn1.crmf;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Time;

public class OptionalValidity
    extends ASN1Object
{
    private Time notBefore;
    private Time notAfter;

    private OptionalValidity(ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            if (tObj.getTagNo() == 0)
            {
                notBefore = Time.getInstance(tObj, true);
            }
            else
            {
                notAfter = Time.getInstance(tObj, true);
            }
        }
    }

    public static OptionalValidity getInstance(Object o)
    {
        if (o instanceof OptionalValidity)
        {
            return (OptionalValidity)o;
        }

        if (o != null)
        {
            return new OptionalValidity(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public OptionalValidity(Time notBefore, Time notAfter)
    {
        if (notBefore == null && notAfter == null)
        {
            throw new IllegalArgumentException("at least one of notBefore/notAfter must not be null.");
        }

        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public Time getNotBefore()
    {
        return notBefore;
    }

    public Time getNotAfter()
    {
        return notAfter;
    }

    /**
     * <pre>
     * OptionalValidity ::= SEQUENCE {
     *                        notBefore  [0] Time OPTIONAL,
     *                        notAfter   [1] Time OPTIONAL } --at least one MUST be present
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (notBefore != null)
        {
            v.add(new DERTaggedObject(true, 0, notBefore));
        }

        if (notAfter != null)
        {
            v.add(new DERTaggedObject(true, 1, notAfter));
        }

        return new DERSequence(v);
    }
}
