package com.google.bitcoin.bouncycastle.asn1.cmp;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERGeneralizedTime;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.crmf.CertId;
import com.google.bitcoin.bouncycastle.asn1.x509.X509Extensions;

public class RevAnnContent
    extends ASN1Encodable
{
    private PKIStatus status;
    private CertId certId;
    private DERGeneralizedTime willBeRevokedAt;
    private DERGeneralizedTime badSinceDate;
    private X509Extensions crlDetails;
    
    private RevAnnContent(ASN1Sequence seq)
    {
        status = PKIStatus.getInstance(seq.getObjectAt(0));
        certId = CertId.getInstance(seq.getObjectAt(1));
        willBeRevokedAt = DERGeneralizedTime.getInstance(seq.getObjectAt(2));
        badSinceDate = DERGeneralizedTime.getInstance(seq.getObjectAt(3));

        if (seq.size() > 4)
        {
            crlDetails = X509Extensions.getInstance(seq.getObjectAt(4));
        }
    }

    public static RevAnnContent getInstance(Object o)
    {
        if (o instanceof RevAnnContent)
        {
            return (RevAnnContent)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new RevAnnContent((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public PKIStatus getStatus()
    {
        return status;
    }

    public CertId getCertId()
    {
        return certId;
    }

    public DERGeneralizedTime getWillBeRevokedAt()
    {
        return willBeRevokedAt;
    }

    public DERGeneralizedTime getBadSinceDate()
    {
        return badSinceDate;
    }

    public X509Extensions getCrlDetails()
    {
        return crlDetails;
    }

    /**
     * <pre>
     * RevAnnContent ::= SEQUENCE {
     *       status              PKIStatus,
     *       certId              CertId,
     *       willBeRevokedAt     GeneralizedTime,
     *       badSinceDate        GeneralizedTime,
     *       crlDetails          Extensions  OPTIONAL
     *        -- extra CRL details (e.g., crl number, reason, location, etc.)
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(status);
        v.add(certId);
        v.add(willBeRevokedAt);
        v.add(badSinceDate);

        if (crlDetails != null)
        {
            v.add(crlDetails);
        }

        return new DERSequence(v);
    }
}
