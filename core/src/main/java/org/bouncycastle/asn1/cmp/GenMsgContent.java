package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class GenMsgContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private GenMsgContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static GenMsgContent getInstance(Object o)
    {
        if (o instanceof GenMsgContent)
        {
            return (GenMsgContent)o;
        }

        if (o != null)
        {
            return new GenMsgContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public GenMsgContent(InfoTypeAndValue itv)
    {
        content = new DERSequence(itv);
    }

    public GenMsgContent(InfoTypeAndValue[] itv)
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
     * GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
