package com.google.bitcoin.bouncycastle.asn1.crmf;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.x509.GeneralName;

public class SinglePubInfo
    extends ASN1Encodable
{
    private DERInteger pubMethod;
    private GeneralName pubLocation;

    private SinglePubInfo(ASN1Sequence seq)
    {
        pubMethod = DERInteger.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            pubLocation = GeneralName.getInstance(seq.getObjectAt(1));
        }
    }

    public static SinglePubInfo getInstance(Object o)
    {
        if (o instanceof SinglePubInfo)
        {
            return (SinglePubInfo)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new SinglePubInfo((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public GeneralName getPubLocation()
    {
        return pubLocation;
    }

    /**
     * <pre>
     * SinglePubInfo ::= SEQUENCE {
     *        pubMethod    INTEGER {
     *           dontCare    (0),
     *           x500        (1),
     *           web         (2),
     *           ldap        (3) },
     *       pubLocation  GeneralName OPTIONAL }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(pubMethod);

        if (pubLocation != null)
        {
            v.add(pubLocation);
        }

        return new DERSequence(v);
    }
}
