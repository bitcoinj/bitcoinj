package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

public class CertConfirmContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private CertConfirmContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static CertConfirmContent getInstance(Object o)
    {
        if (o instanceof CertConfirmContent)
        {
            return (CertConfirmContent)o;
        }

        if (o != null)
        {
            return new CertConfirmContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertStatus[] toCertStatusArray()
    {
        CertStatus[] result = new CertStatus[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = CertStatus.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * CertConfirmContent ::= SEQUENCE OF CertStatus
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
