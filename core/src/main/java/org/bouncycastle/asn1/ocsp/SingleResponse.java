package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509Extensions;

public class SingleResponse
    extends ASN1Object
{
    private CertID              certID;
    private CertStatus          certStatus;
    private ASN1GeneralizedTime  thisUpdate;
    private ASN1GeneralizedTime  nextUpdate;
    private Extensions      singleExtensions;

    /**
     * @deprecated use method taking ASN1GeneralizedTime and Extensions
     * @param certID
     * @param certStatus
     * @param thisUpdate
     * @param nextUpdate
     * @param singleExtensions
     */
    public SingleResponse(
        CertID              certID,
        CertStatus          certStatus,
        ASN1GeneralizedTime thisUpdate,
        ASN1GeneralizedTime nextUpdate,
        X509Extensions singleExtensions)
    {
        this(certID, certStatus, thisUpdate, nextUpdate, Extensions.getInstance(singleExtensions));
    }

    public SingleResponse(
        CertID              certID,
        CertStatus          certStatus,
        ASN1GeneralizedTime thisUpdate,
        ASN1GeneralizedTime nextUpdate,
        Extensions          singleExtensions)
    {
        this.certID = certID;
        this.certStatus = certStatus;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.singleExtensions = singleExtensions;
    }

    private SingleResponse(
        ASN1Sequence    seq)
    {
        this.certID = CertID.getInstance(seq.getObjectAt(0));
        this.certStatus = CertStatus.getInstance(seq.getObjectAt(1));
        this.thisUpdate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));

        if (seq.size() > 4)
        {
            this.nextUpdate = ASN1GeneralizedTime.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(3), true);
            this.singleExtensions = Extensions.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(4), true);
        }
        else if (seq.size() > 3)
        {
            ASN1TaggedObject    o = (ASN1TaggedObject)seq.getObjectAt(3);

            if (o.getTagNo() == 0)
            {
                this.nextUpdate = ASN1GeneralizedTime.getInstance(o, true);
            }
            else
            {
                this.singleExtensions = Extensions.getInstance(o, true);
            }
        }
    }

    public static SingleResponse getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SingleResponse getInstance(
        Object  obj)
    {
        if (obj instanceof SingleResponse)
        {
            return (SingleResponse)obj;
        }
        else if (obj != null)
        {
            return new SingleResponse(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public CertID getCertID()
    {
        return certID;
    }

    public CertStatus getCertStatus()
    {
        return certStatus;
    }

    public ASN1GeneralizedTime getThisUpdate()
    {
        return thisUpdate;
    }

    public ASN1GeneralizedTime getNextUpdate()
    {
        return nextUpdate;
    }

    public Extensions getSingleExtensions()
    {
        return singleExtensions;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  SingleResponse ::= SEQUENCE {
     *          certID                       CertID,
     *          certStatus                   CertStatus,
     *          thisUpdate                   GeneralizedTime,
     *          nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
     *          singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certID);
        v.add(certStatus);
        v.add(thisUpdate);

        if (nextUpdate != null)
        {
            v.add(new DERTaggedObject(true, 0, nextUpdate));
        }

        if (singleExtensions != null)
        {
            v.add(new DERTaggedObject(true, 1, singleExtensions));
        }

        return new DERSequence(v);
    }
}
