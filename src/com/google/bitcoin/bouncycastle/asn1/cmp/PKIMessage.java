package com.google.bitcoin.bouncycastle.asn1.cmp;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERBitString;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;

import java.util.Enumeration;

public class PKIMessage
    extends ASN1Encodable
{
    private PKIHeader header;
    private PKIBody body;
    private DERBitString protection;
    private ASN1Sequence extraCerts;

    private PKIMessage(ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();

        header = PKIHeader.getInstance(en.nextElement());
        body = PKIBody.getInstance(en.nextElement());

        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            if (tObj.getTagNo() == 0)
            {
                protection = DERBitString.getInstance(tObj, true);
            }
            else
            {
                extraCerts = ASN1Sequence.getInstance(tObj, true);
            }
        }
    }

    public static PKIMessage getInstance(Object o)
    {
        if (o instanceof PKIMessage)
        {
            return (PKIMessage)o;
        }

        if (o instanceof ASN1Sequence)
        {
            return new PKIMessage((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public PKIHeader getHeader()
    {
        return header;
    }

    public PKIBody getBody()
    {
        return body;
    }

    /**
     * <pre>
     * PKIMessage ::= SEQUENCE {
     *                  header           PKIHeader,
     *                  body             PKIBody,
     *                  protection   [0] PKIProtection OPTIONAL,
     *                  extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                                                                     OPTIONAL
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(header);
        v.add(body);

        addOptional(v, 0, protection);
        addOptional(v, 1, extraCerts);

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
