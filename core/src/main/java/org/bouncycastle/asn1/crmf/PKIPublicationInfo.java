package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class PKIPublicationInfo
    extends ASN1Object
{
    private ASN1Integer action;
    private ASN1Sequence pubInfos;

    private PKIPublicationInfo(ASN1Sequence seq)
    {
        action = ASN1Integer.getInstance(seq.getObjectAt(0));
        pubInfos = ASN1Sequence.getInstance(seq.getObjectAt(1));
    }

    public static PKIPublicationInfo getInstance(Object o)
    {
        if (o instanceof PKIPublicationInfo)
        {
            return (PKIPublicationInfo)o;
        }

        if (o != null)
        {
            return new PKIPublicationInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Integer getAction()
    {
        return action;
    }

    public SinglePubInfo[] getPubInfos()
    {
        if (pubInfos == null)
        {
            return null;
        }

        SinglePubInfo[] results = new SinglePubInfo[pubInfos.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = SinglePubInfo.getInstance(pubInfos.getObjectAt(i));
        }

        return results;
    }

    /**
     * <pre>
     * PKIPublicationInfo ::= SEQUENCE {
     *                  action     INTEGER {
     *                                 dontPublish (0),
     *                                 pleasePublish (1) },
     *                  pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
     * -- pubInfos MUST NOT be present if action is "dontPublish"
     * -- (if action is "pleasePublish" and pubInfos is omitted,
     * -- "dontCare" is assumed)
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(action);
        v.add(pubInfos);

        return new DERSequence(v);
    }
}
