package com.google.bitcoin.bouncycastle.asn1.cmp;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERBitString;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;
import com.google.bitcoin.bouncycastle.asn1.crmf.CertId;
import com.google.bitcoin.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class OOBCertHash
    extends ASN1Encodable
{
    private AlgorithmIdentifier hashAlg;
    private CertId certId;
    private DERBitString  hashVal;

    private OOBCertHash(ASN1Sequence seq)
    {
        int index = seq.size() - 1;

        hashVal = DERBitString.getInstance(seq.getObjectAt(index--));

        for (int i = index; i >= 0; i--)
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)seq.getObjectAt(i);

            if (tObj.getTagNo() == 0)
            {
                hashAlg = AlgorithmIdentifier.getInstance(tObj, true);
            }
            else
            {
                certId = CertId.getInstance(tObj, true);
            }
        }

    }

    public static OOBCertHash getInstance(Object o)
    {
        if (o instanceof OOBCertHash)
        {
            return (OOBCertHash)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new OOBCertHash((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public AlgorithmIdentifier getHashAlg()
    {
        return hashAlg;
    }

    public CertId getCertId()
    {
        return certId;
    }

    /**
     * <pre>
     * OOBCertHash ::= SEQUENCE {
     *                      hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
     *                      certId      [1] CertId                  OPTIONAL,
     *                      hashVal         BIT STRING
     *                      -- hashVal is calculated over the DER encoding of the
     *                      -- self-signed certificate with the identifier certID.
     *       }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        addOptional(v, 0, hashAlg);
        addOptional(v, 1, certId);

        v.add(hashVal);

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
