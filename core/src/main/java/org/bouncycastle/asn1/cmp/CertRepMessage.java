package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class CertRepMessage
    extends ASN1Object
{
    private ASN1Sequence caPubs;
    private ASN1Sequence response;

    private CertRepMessage(ASN1Sequence seq)
    {
        int index = 0;

        if (seq.size() > 1)
        {
            caPubs = ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
        }

        response = ASN1Sequence.getInstance(seq.getObjectAt(index));
    }

    public static CertRepMessage getInstance(Object o)
    {
        if (o instanceof CertRepMessage)
        {
            return (CertRepMessage)o;
        }

        if (o != null)
        {
            return new CertRepMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertRepMessage(CMPCertificate[] caPubs, CertResponse[] response)
    {
        if (response == null)
        {
            throw new IllegalArgumentException("'response' cannot be null");
        }

        if (caPubs != null)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            for (int i = 0; i < caPubs.length; i++)
            {
                v.add(caPubs[i]);
            }
            this.caPubs = new DERSequence(v);
        }

        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            for (int i = 0; i < response.length; i++)
            {
                v.add(response[i]);
            }
            this.response = new DERSequence(v);
        }
    }

    public CMPCertificate[] getCaPubs()
    {
        if (caPubs == null)
        {
            return null;
        }

        CMPCertificate[] results = new CMPCertificate[caPubs.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = CMPCertificate.getInstance(caPubs.getObjectAt(i));
        }

        return results;
    }

    public CertResponse[] getResponse()
    {
        CertResponse[] results = new CertResponse[response.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = CertResponse.getInstance(response.getObjectAt(i));
        }

        return results;
    }

    /**
     * <pre>
     * CertRepMessage ::= SEQUENCE {
     *                          caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                                                                             OPTIONAL,
     *                          response         SEQUENCE OF CertResponse
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (caPubs != null)
        {
            v.add(new DERTaggedObject(true, 1, caPubs));
        }

        v.add(response);

        return new DERSequence(v);
    }
}
