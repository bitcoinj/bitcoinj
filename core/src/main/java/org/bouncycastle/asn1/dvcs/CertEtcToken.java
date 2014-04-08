package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.smime.SMIMECapabilities;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;

/**
 * <pre>
 * CertEtcToken ::= CHOICE {
 *         certificate                  [0] IMPLICIT Certificate ,
 *         esscertid                    [1] ESSCertId ,
 *         pkistatus                    [2] IMPLICIT PKIStatusInfo ,
 *         assertion                    [3] ContentInfo ,
 *         crl                          [4] IMPLICIT CertificateList,
 *         ocspcertstatus               [5] CertStatus,
 *         oscpcertid                   [6] IMPLICIT CertId ,
 *         oscpresponse                 [7] IMPLICIT OCSPResponse,
 *         capabilities                 [8] SMIMECapabilities,
 *         extension                    Extension
 * }
 * </pre>
 */
public class CertEtcToken
    extends ASN1Object
    implements ASN1Choice
{
    public static final int TAG_CERTIFICATE = 0;
    public static final int TAG_ESSCERTID = 1;
    public static final int TAG_PKISTATUS = 2;
    public static final int TAG_ASSERTION = 3;
    public static final int TAG_CRL = 4;
    public static final int TAG_OCSPCERTSTATUS = 5;
    public static final int TAG_OCSPCERTID = 6;
    public static final int TAG_OCSPRESPONSE = 7;
    public static final int TAG_CAPABILITIES = 8;

    private static final boolean[] explicit = new boolean[]
        {
            false, true, false, true, false, true, false, false, true
        };

    private int tagNo;
    private ASN1Encodable value;
    private Extension extension;

    public CertEtcToken(int tagNo, ASN1Encodable value)
    {
        this.tagNo = tagNo;
        this.value = value;
    }

    public CertEtcToken(Extension extension)
    {
        this.tagNo = -1;
        this.extension = extension;
    }

    private CertEtcToken(ASN1TaggedObject choice)
    {
        this.tagNo = choice.getTagNo();

        switch (tagNo)
        {
        case TAG_CERTIFICATE:
            value = Certificate.getInstance(choice, false);
            break;
        case TAG_ESSCERTID:
            value = ESSCertID.getInstance(choice.getObject());
            break;
        case TAG_PKISTATUS:
            value = PKIStatusInfo.getInstance(choice, false);
            break;
        case TAG_ASSERTION:
            value = ContentInfo.getInstance(choice.getObject());
            break;
        case TAG_CRL:
            value = CertificateList.getInstance(choice, false);
            break;
        case TAG_OCSPCERTSTATUS:
            value = CertStatus.getInstance(choice.getObject());
            break;
        case TAG_OCSPCERTID:
            value = CertID.getInstance(choice, false);
            break;
        case TAG_OCSPRESPONSE:
            value = OCSPResponse.getInstance(choice, false);
            break;
        case TAG_CAPABILITIES:
            value = SMIMECapabilities.getInstance(choice.getObject());
            break;
        default:
            throw new IllegalArgumentException("Unknown tag: " + tagNo);
        }
    }

    public static CertEtcToken getInstance(Object obj)
    {
        if (obj instanceof CertEtcToken)
        {
            return (CertEtcToken)obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new CertEtcToken((ASN1TaggedObject)obj);
        }
        else if (obj != null)
        {
            return new CertEtcToken(Extension.getInstance(obj));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (extension == null)
        {
            return new DERTaggedObject(explicit[tagNo], tagNo, value);
        }
        else
        {
            return extension.toASN1Primitive();
        }
    }

    public int getTagNo()
    {
        return tagNo;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public Extension getExtension()
    {
        return extension;
    }

    public String toString()
    {
        return "CertEtcToken {\n" + value + "}\n";
    }

    public static CertEtcToken[] arrayFromSequence(ASN1Sequence seq)
    {
        CertEtcToken[] tmp = new CertEtcToken[seq.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = CertEtcToken.getInstance(seq.getObjectAt(i));
        }

        return tmp;
    }
}
