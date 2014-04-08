package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class PKIMessages
    extends ASN1Object
{
    private ASN1Sequence content;

    private PKIMessages(ASN1Sequence seq)
    {
        content = seq;
    }

    public static PKIMessages getInstance(Object o)
    {
        if (o instanceof PKIMessages)
        {
            return (PKIMessages)o;
        }

        if (o != null)
        {
            return new PKIMessages(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PKIMessages(PKIMessage msg)
    {
        content = new DERSequence(msg);
    }

    public PKIMessages(PKIMessage[] msgs)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < msgs.length; i++)
        {
            v.add(msgs[i]);
        }
        content = new DERSequence(v);
    }

    public PKIMessage[] toPKIMessageArray()
    {
        PKIMessage[] result = new PKIMessage[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = PKIMessage.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
