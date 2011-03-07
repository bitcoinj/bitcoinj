package com.google.bitcoin.bouncycastle.asn1.cmp;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERObject;

public class PKIMessages
    extends ASN1Encodable
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

        if (o instanceof ASN1Sequence)
        {
            return new PKIMessages((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
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
    public DERObject toASN1Object()
    {
        return content;
    }
}
