package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class GenRepContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private GenRepContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static GenRepContent getInstance(Object o)
    {
        if (o instanceof GenRepContent)
        {
            return (GenRepContent)o;
        }

        if (o != null)
        {
            return new GenRepContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public GenRepContent(InfoTypeAndValue itv)
    {
        content = new DERSequence(itv);
    }

    public GenRepContent(InfoTypeAndValue[] itv)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < itv.length; i++)
        {
            v.add(itv[i]);
        }
        content = new DERSequence(v);
    }

    public InfoTypeAndValue[] toInfoTypeAndValueArray()
    {
        InfoTypeAndValue[] result = new InfoTypeAndValue[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = InfoTypeAndValue.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * GenRepContent ::= SEQUENCE OF InfoTypeAndValue
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
