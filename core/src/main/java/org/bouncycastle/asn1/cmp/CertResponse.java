package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class CertResponse
    extends ASN1Object
{
    private ASN1Integer certReqId;
    private PKIStatusInfo status;
    private CertifiedKeyPair certifiedKeyPair;
    private ASN1OctetString rspInfo;

    private CertResponse(ASN1Sequence seq)
    {
        certReqId = ASN1Integer.getInstance(seq.getObjectAt(0));
        status = PKIStatusInfo.getInstance(seq.getObjectAt(1));

        if (seq.size() >= 3)
        {
            if (seq.size() == 3)
            {
                ASN1Encodable o = seq.getObjectAt(2);
                if (o instanceof ASN1OctetString)
                {
                    rspInfo = ASN1OctetString.getInstance(o);
                }
                else
                {
                    certifiedKeyPair = CertifiedKeyPair.getInstance(o);
                }
            }
            else
            {
                certifiedKeyPair = CertifiedKeyPair.getInstance(seq.getObjectAt(2));
                rspInfo = ASN1OctetString.getInstance(seq.getObjectAt(3));
            }
        }
    }

    public static CertResponse getInstance(Object o)
    {
        if (o instanceof CertResponse)
        {
            return (CertResponse)o;
        }

        if (o != null)
        {
            return new CertResponse(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertResponse(
        ASN1Integer certReqId,
        PKIStatusInfo status)
    {
        this(certReqId, status, null, null);
    }

    public CertResponse(
        ASN1Integer certReqId,
        PKIStatusInfo status,
        CertifiedKeyPair certifiedKeyPair,
        ASN1OctetString rspInfo)
    {
        if (certReqId == null)
        {
            throw new IllegalArgumentException("'certReqId' cannot be null");
        }
        if (status == null)
        {
            throw new IllegalArgumentException("'status' cannot be null");
        }
        this.certReqId = certReqId;
        this.status = status;
        this.certifiedKeyPair = certifiedKeyPair;
        this.rspInfo = rspInfo;
    }

    public ASN1Integer getCertReqId()
    {
        return certReqId;
    }

    public PKIStatusInfo getStatus()
    {
        return status;
    }

    public CertifiedKeyPair getCertifiedKeyPair()
    {
        return certifiedKeyPair;
    }

    /**
     * <pre>
     * CertResponse ::= SEQUENCE {
     *                            certReqId           INTEGER,
     *                            -- to match this response with corresponding request (a value
     *                            -- of -1 is to be used if certReqId is not specified in the
     *                            -- corresponding request)
     *                            status              PKIStatusInfo,
     *                            certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
     *                            rspInfo             OCTET STRING        OPTIONAL
     *                            -- analogous to the id-regInfo-utf8Pairs string defined
     *                            -- for regInfo in CertReqMsg [CRMF]
     *             }
     * </pre> 
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certReqId);
        v.add(status);

        if (certifiedKeyPair != null)
        {
            v.add(certifiedKeyPair);
        }

        if (rspInfo != null)
        {
            v.add(rspInfo);
        }
        
        return new DERSequence(v);
    }
}
