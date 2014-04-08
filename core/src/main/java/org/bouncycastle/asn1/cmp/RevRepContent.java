package org.bouncycastle.asn1.cmp;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.x509.CertificateList;

public class RevRepContent
    extends ASN1Object
{
    private ASN1Sequence status;
    private ASN1Sequence revCerts;
    private ASN1Sequence crls;

    private RevRepContent(ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();

        status = ASN1Sequence.getInstance(en.nextElement());
        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(en.nextElement());

            if (tObj.getTagNo() == 0)
            {
                revCerts = ASN1Sequence.getInstance(tObj, true);
            }
            else
            {
                crls = ASN1Sequence.getInstance(tObj, true);
            }
        }
    }

    public static RevRepContent getInstance(Object o)
    {
        if (o instanceof RevRepContent)
        {
            return (RevRepContent)o;
        }

        if (o != null)
        {
            return new RevRepContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PKIStatusInfo[] getStatus()
    {
        PKIStatusInfo[] results = new PKIStatusInfo[status.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = PKIStatusInfo.getInstance(status.getObjectAt(i));
        }

        return results;
    }

    public CertId[] getRevCerts()
    {
        if (revCerts == null)
        {
            return null;
        }

        CertId[] results = new CertId[revCerts.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = CertId.getInstance(revCerts.getObjectAt(i));
        }

        return results;
    }

    public CertificateList[] getCrls()
    {
        if (crls == null)
        {
            return null;
        }

        CertificateList[] results = new CertificateList[crls.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = CertificateList.getInstance(crls.getObjectAt(i));
        }

        return results;
    }

    /**
     * <pre>
     * RevRepContent ::= SEQUENCE {
     *        status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
     *        -- in same order as was sent in RevReqContent
     *        revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
     *        -- IDs for which revocation was requested
     *        -- (same order as status)
     *        crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL
     *        -- the resulting CRLs (there may be more than one)
     *   }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(status);

        addOptional(v, 0, revCerts);
        addOptional(v, 1, crls);

        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}
