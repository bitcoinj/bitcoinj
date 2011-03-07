package com.google.bitcoin.bouncycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;

public class DHParameter
    extends ASN1Encodable
{
    DERInteger      p, g, l;

    public DHParameter(
        BigInteger  p,
        BigInteger  g,
        int         l)
    {
        this.p = new DERInteger(p);
        this.g = new DERInteger(g);

        if (l != 0)
        {
            this.l = new DERInteger(l);
        }
        else
        {
            this.l = null;
        }
    }

    public DHParameter(
        ASN1Sequence  seq)
    {
        Enumeration     e = seq.getObjects();

        p = (DERInteger)e.nextElement();
        g = (DERInteger)e.nextElement();

        if (e.hasMoreElements())
        {
            l = (DERInteger)e.nextElement();
        }
        else
        {
            l = null;
        }
    }

    public BigInteger getP()
    {
        return p.getPositiveValue();
    }

    public BigInteger getG()
    {
        return g.getPositiveValue();
    }

    public BigInteger getL()
    {
        if (l == null)
        {
            return null;
        }

        return l.getPositiveValue();
    }

    public DERObject toASN1Object()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(p);
        v.add(g);

        if (this.getL() != null)
        {
            v.add(l);
        }

        return new DERSequence(v);
    }
}
