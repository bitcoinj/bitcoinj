package com.google.bitcoin.bouncycastle.asn1.crmf;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.x509.GeneralName;

public class CertId
    extends ASN1Encodable
{
    private GeneralName issuer;
    private DERInteger serialNumber;

    private CertId(ASN1Sequence seq)
    {
        issuer = GeneralName.getInstance(seq.getObjectAt(0));
        serialNumber = DERInteger.getInstance(seq.getObjectAt(1));
    }

    public static CertId getInstance(Object o)
    {
        if (o instanceof CertId)
        {
            return (CertId)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new CertId((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public static CertId getInstance(ASN1TaggedObject obj, boolean isExplicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    public GeneralName getIssuer()
    {
        return issuer;
    }

    public DERInteger getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * <pre>
     * CertId ::= SEQUENCE {
     *                 issuer           GeneralName,
     *                 serialNumber     INTEGER }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(issuer);
        v.add(serialNumber);
        
        return new DERSequence(v);
    }
}
