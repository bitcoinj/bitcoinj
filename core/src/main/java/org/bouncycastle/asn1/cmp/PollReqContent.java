package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class PollReqContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private PollReqContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static PollReqContent getInstance(Object o)
    {
        if (o instanceof PollReqContent)
        {
            return (PollReqContent)o;
        }

        if (o != null)
        {
            return new PollReqContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * Create a pollReqContent for a single certReqId.
     *
     * @param certReqId the certificate request ID.
     */
    public PollReqContent(ASN1Integer certReqId)
    {
        this(new DERSequence(new DERSequence(certReqId)));
    }

    public ASN1Integer[][] getCertReqIds()
    {
        ASN1Integer[][] result = new ASN1Integer[content.size()][];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = sequenceToASN1IntegerArray((ASN1Sequence)content.getObjectAt(i));
        }

        return result;
    }

    private static ASN1Integer[] sequenceToASN1IntegerArray(ASN1Sequence seq)
    {
         ASN1Integer[] result = new ASN1Integer[seq.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1Integer.getInstance(seq.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * PollReqContent ::= SEQUENCE OF SEQUENCE {
     *                        certReqId              INTEGER
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
