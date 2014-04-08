package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
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

public class DVCSCertInfoBuilder
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

    public DVCSCertInfoBuilder(
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

    public DVCSCertInfo build()
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

        return DVCSCertInfo.getInstance(new DERSequence(v));
    }

    public void setVersion(int version)
    {
        this.version = version;
    }

    public void setDvReqInfo(DVCSRequestInformation dvReqInfo)
    {
        this.dvReqInfo = dvReqInfo;
    }

    public void setMessageImprint(DigestInfo messageImprint)
    {
        this.messageImprint = messageImprint;
    }

    public void setSerialNumber(ASN1Integer serialNumber)
    {
        this.serialNumber = serialNumber;
    }

    public void setResponseTime(DVCSTime responseTime)
    {
        this.responseTime = responseTime;
    }

    public void setDvStatus(PKIStatusInfo dvStatus)
    {
        this.dvStatus = dvStatus;
    }

    public void setPolicy(PolicyInformation policy)
    {
        this.policy = policy;
    }

    public void setReqSignature(ASN1Set reqSignature)
    {
        this.reqSignature = reqSignature;
    }

    public void setCerts(TargetEtcChain[] certs)
    {
        this.certs = new DERSequence(certs);
    }

    public void setExtensions(Extensions extensions)
    {
        this.extensions = extensions;
    }

}
