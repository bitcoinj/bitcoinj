package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.PolicyInformation;

/**
 * <pre>
 *     DVCSCertInfo::= SEQUENCE  {
 *         version             Integer DEFAULT 1 ,
 *         dvReqInfo           DVCSRequestInformation,
 *         messageImprint      DigestInfo,
 *         serialNumber        Integer,
 *         responseTime        DVCSTime,
 *         dvStatus            [0] PKIStatusInfo OPTIONAL,
 *         policy              [1] PolicyInformation OPTIONAL,
 *         reqSignature        [2] SignerInfos  OPTIONAL,
 *         certs               [3] SEQUENCE SIZE (1..MAX) OF
 *                                 TargetEtcChain OPTIONAL,
 *         extensions          Extensions OPTIONAL
 *     }
 * </pre>
 */

public class DVCSCertInfo
    extends ASN1Object
{

    private int version = DEFAULT_VERSION;
    private DVCSRequestInformation dvReqInfo;
    private DigestInfo messageImprint;
    private ASN1Integer serialNumber;
    private DVCSTime responseTime;
    private PKIStatusInfo dvStatus;
    private PolicyInformation policy;
    private ASN1Set reqSignature;
    private ASN1Sequence certs;
    private Extensions extensions;

    private static final int DEFAULT_VERSION = 1;
    private static final int TAG_DV_STATUS = 0;
    private static final int TAG_POLICY = 1;
    private static final int TAG_REQ_SIGNATURE = 2;
    private static final int TAG_CERTS = 3;

    public DVCSCertInfo(
        DVCSRequestInformation dvReqInfo,
        DigestInfo messageImprint,
        ASN1Integer serialNumber,
        DVCSTime responseTime)
    {
        this.dvReqInfo = dvReqInfo;
        this.messageImprint = messageImprint;
        this.serialNumber = serialNumber;
        this.responseTime = responseTime;
    }

    private DVCSCertInfo(ASN1Sequence seq)
    {
        int i = 0;
        ASN1Encodable x = seq.getObjectAt(i++);
        try
        {
            ASN1Integer encVersion = ASN1Integer.getInstance(x);
            this.version = encVersion.getValue().intValue();
            x = seq.getObjectAt(i++);
        }
        catch (IllegalArgumentException e)
        {
        }

        this.dvReqInfo = DVCSRequestInformation.getInstance(x);
        x = seq.getObjectAt(i++);
        this.messageImprint = DigestInfo.getInstance(x);
        x = seq.getObjectAt(i++);
        this.serialNumber = ASN1Integer.getInstance(x);
        x = seq.getObjectAt(i++);
        this.responseTime = DVCSTime.getInstance(x);

        while (i < seq.size())
        {

            x = seq.getObjectAt(i++);

            try
            {
                ASN1TaggedObject t = ASN1TaggedObject.getInstance(x);
                int tagNo = t.getTagNo();

                switch (tagNo)
                {
                case TAG_DV_STATUS:
                    this.dvStatus = PKIStatusInfo.getInstance(t, false);
                    break;
                case TAG_POLICY:
                    this.policy = PolicyInformation.getInstance(ASN1Sequence.getInstance(t, false));
                    break;
                case TAG_REQ_SIGNATURE:
                    this.reqSignature = ASN1Set.getInstance(t, false);
                    break;
                case TAG_CERTS:
                    this.certs = ASN1Sequence.getInstance(t, false);
                    break;
                }

                continue;

            }
            catch (IllegalArgumentException e)
            {
            }

            try
            {
                this.extensions = Extensions.getInstance(x);
            }
            catch (IllegalArgumentException e)
            {
            }

        }

    }

    public static DVCSCertInfo getInstance(Object obj)
    {
        if (obj instanceof DVCSCertInfo)
        {
            return (DVCSCertInfo)obj;
        }
        else if (obj != null)
        {
            return new DVCSCertInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static DVCSCertInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector v = new ASN1EncodableVector();

        if (version != DEFAULT_VERSION)
        {
            v.add(new ASN1Integer(version));
        }
        v.add(dvReqInfo);
        v.add(messageImprint);
        v.add(serialNumber);
        v.add(responseTime);
        if (dvStatus != null)
        {
            v.add(new DERTaggedObject(false, TAG_DV_STATUS, dvStatus));
        }
        if (policy != null)
        {
            v.add(new DERTaggedObject(false, TAG_POLICY, policy));
        }
        if (reqSignature != null)
        {
            v.add(new DERTaggedObject(false, TAG_REQ_SIGNATURE, reqSignature));
        }
        if (certs != null)
        {
            v.add(new DERTaggedObject(false, TAG_CERTS, certs));
        }
        if (extensions != null)
        {
            v.add(extensions);
        }

        return new DERSequence(v);
    }

    public String toString()
    {
        StringBuffer s = new StringBuffer();

        s.append("DVCSCertInfo {\n");

        if (version != DEFAULT_VERSION)
        {
            s.append("version: " + version + "\n");
        }
        s.append("dvReqInfo: " + dvReqInfo + "\n");
        s.append("messageImprint: " + messageImprint + "\n");
        s.append("serialNumber: " + serialNumber + "\n");
        s.append("responseTime: " + responseTime + "\n");
        if (dvStatus != null)
        {
            s.append("dvStatus: " + dvStatus + "\n");
        }
        if (policy != null)
        {
            s.append("policy: " + policy + "\n");
        }
        if (reqSignature != null)
        {
            s.append("reqSignature: " + reqSignature + "\n");
        }
        if (certs != null)
        {
            s.append("certs: " + certs + "\n");
        }
        if (extensions != null)
        {
            s.append("extensions: " + extensions + "\n");
        }

        s.append("}\n");
        return s.toString();
    }

    public int getVersion()
    {
        return version;
    }

    private void setVersion(int version)
    {
        this.version = version;
    }

    public DVCSRequestInformation getDvReqInfo()
    {
        return dvReqInfo;
    }

    private void setDvReqInfo(DVCSRequestInformation dvReqInfo)
    {
        this.dvReqInfo = dvReqInfo;
    }

    public DigestInfo getMessageImprint()
    {
        return messageImprint;
    }

    private void setMessageImprint(DigestInfo messageImprint)
    {
        this.messageImprint = messageImprint;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    public DVCSTime getResponseTime()
    {
        return responseTime;
    }

    public PKIStatusInfo getDvStatus()
    {
        return dvStatus;
    }

    public PolicyInformation getPolicy()
    {
        return policy;
    }

    public ASN1Set getReqSignature()
    {
        return reqSignature;
    }

    public TargetEtcChain[] getCerts()
    {
        if (certs != null)
        {
            return TargetEtcChain.arrayFromSequence(certs);
        }

        return null;
    }

    public Extensions getExtensions()
    {
        return extensions;
    }
}
