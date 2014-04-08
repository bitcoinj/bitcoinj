package org.bouncycastle.asn1.ua;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class DSTU4145BinaryField
    extends ASN1Object
{

    private int m, k, j, l;

    private DSTU4145BinaryField(ASN1Sequence seq)
    {
        m = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue().intValue();

        if (seq.getObjectAt(1) instanceof ASN1Integer)
        {
            k = ((ASN1Integer)seq.getObjectAt(1)).getPositiveValue().intValue();
        }
        else if (seq.getObjectAt(1) instanceof ASN1Sequence)
        {
            ASN1Sequence coefs = ASN1Sequence.getInstance(seq.getObjectAt(1));

            k = ASN1Integer.getInstance(coefs.getObjectAt(0)).getPositiveValue().intValue();
            j = ASN1Integer.getInstance(coefs.getObjectAt(1)).getPositiveValue().intValue();
            l = ASN1Integer.getInstance(coefs.getObjectAt(2)).getPositiveValue().intValue();
        }
        else
        {
            throw new IllegalArgumentException("object parse error");
        }
    }

    public static DSTU4145BinaryField getInstance(Object obj)
    {
        if (obj instanceof DSTU4145BinaryField)
        {
            return (DSTU4145BinaryField)obj;
        }

        if (obj != null)
        {
            return new DSTU4145BinaryField(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public DSTU4145BinaryField(int m, int k1, int k2, int k3)
    {
        this.m = m;
        this.k = k1;
        this.j = k2;
        this.l = k3;
    }

    public int getM()
    {
        return m;
    }

    public int getK1()
    {
        return k;
    }

    public int getK2()
    {
        return j;
    }

    public int getK3()
    {
        return l;
    }

    public DSTU4145BinaryField(int m, int k)
    {
        this(m, k, 0, 0);
    }

    /**
     * BinaryField ::= SEQUENCE {
     * M INTEGER,
     * CHOICE {Trinomial,    Pentanomial}
     * Trinomial::= INTEGER
     * Pentanomial::= SEQUENCE {
     * k INTEGER,
     * j INTEGER,
     * l INTEGER}
     */
    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(m));
        if (j == 0) //Trinomial
        {
            v.add(new ASN1Integer(k));
        }
        else
        {
            ASN1EncodableVector coefs = new ASN1EncodableVector();
            coefs.add(new ASN1Integer(k));
            coefs.add(new ASN1Integer(j));
            coefs.add(new ASN1Integer(l));

            v.add(new DERSequence(coefs));
        }

        return new DERSequence(v);
    }

}
