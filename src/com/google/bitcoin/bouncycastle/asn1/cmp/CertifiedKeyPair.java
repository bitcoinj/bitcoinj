package com.google.bitcoin.bouncycastle.asn1.cmp;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;
import com.google.bitcoin.bouncycastle.asn1.crmf.EncryptedValue;
import com.google.bitcoin.bouncycastle.asn1.crmf.PKIPublicationInfo;

public class CertifiedKeyPair
    extends ASN1Encodable
{
    private CertOrEncCert certOrEncCert;
    private EncryptedValue privateKey;
    private PKIPublicationInfo  publicationInfo;

    private CertifiedKeyPair(ASN1Sequence seq)
    {
        certOrEncCert = CertOrEncCert.getInstance(seq.getObjectAt(0));

        if (seq.size() >= 2)
        {
            if (seq.size() == 2)
            {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                if (tagged.getTagNo() == 0)
                {
                    privateKey = EncryptedValue.getInstance(tagged.getObject());
                }
                else
                {
                    publicationInfo = PKIPublicationInfo.getInstance(tagged.getObject());
                }
            }
            else
            {
                privateKey = EncryptedValue.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)));
                publicationInfo = PKIPublicationInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2)));
            }
        }
    }

    public static CertifiedKeyPair getInstance(Object o)
    {
        if (o instanceof CertifiedKeyPair)
        {
            return (CertifiedKeyPair)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new CertifiedKeyPair((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public CertOrEncCert getCertOrEncCert()
    {
        return certOrEncCert;
    }

    public EncryptedValue getPrivateKey()
    {
        return privateKey;
    }

    public PKIPublicationInfo getPublicationInfo()
    {
        return publicationInfo;
    }

    /**
     * <pre>
     * CertifiedKeyPair ::= SEQUENCE {
     *                                  certOrEncCert       CertOrEncCert,
     *                                  privateKey      [0] EncryptedValue      OPTIONAL,
     *                                  -- see [CRMF] for comment on encoding
     *                                  publicationInfo [1] PKIPublicationInfo  OPTIONAL
     *       }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(certOrEncCert);

        if (privateKey != null)
        {
            v.add(new DERTaggedObject(true, 0, privateKey));
        }

        if (publicationInfo != null)
        {
            v.add(new DERTaggedObject(true, 1, publicationInfo));
        }

        return new DERSequence(v);
    }
}
