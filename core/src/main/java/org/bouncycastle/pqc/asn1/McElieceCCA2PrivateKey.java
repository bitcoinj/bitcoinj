package org.bouncycastle.pqc.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class McElieceCCA2PrivateKey
    extends ASN1Object
{
    private ASN1ObjectIdentifier oid;
    private int n;
    private int k;
    private byte[] encField;
    private byte[] encGp;
    private byte[] encP;
    private byte[] encH;
    private byte[][] encqInv;


    public McElieceCCA2PrivateKey(ASN1ObjectIdentifier oid, int n, int k, GF2mField field, PolynomialGF2mSmallM goppaPoly, Permutation p, GF2Matrix h, PolynomialGF2mSmallM[] qInv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        this.encField = field.getEncoded();
        this.encGp = goppaPoly.getEncoded();
        this.encP = p.getEncoded();
        this.encH = h.getEncoded();
        this.encqInv = new byte[qInv.length][];

        for (int i = 0; i != qInv.length; i++)
        {
            encqInv[i] = qInv[i].getEncoded();
        }
    }

    private McElieceCCA2PrivateKey(ASN1Sequence seq)
    {
        oid = ((ASN1ObjectIdentifier)seq.getObjectAt(0));

        BigInteger bigN = ((ASN1Integer)seq.getObjectAt(1)).getValue();
        n = bigN.intValue();

        BigInteger bigK = ((ASN1Integer)seq.getObjectAt(2)).getValue();
        k = bigK.intValue();

        encField = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();

        encGp = ((ASN1OctetString)seq.getObjectAt(4)).getOctets();

        encP = ((ASN1OctetString)seq.getObjectAt(5)).getOctets();

        encH = ((ASN1OctetString)seq.getObjectAt(6)).getOctets();

        ASN1Sequence asnQInv = (ASN1Sequence)seq.getObjectAt(7);
        encqInv = new byte[asnQInv.size()][];
        for (int i = 0; i < asnQInv.size(); i++)
        {
            encqInv[i] = ((ASN1OctetString)asnQInv.getObjectAt(i)).getOctets();
        }
    }

    public ASN1ObjectIdentifier getOID()
    {
        return oid;
    }

    public int getN()
    {
        return n;
    }

    public int getK()
    {
        return k;
    }

    public GF2mField getField()
    {
        return new GF2mField(encField);
    }

    public PolynomialGF2mSmallM getGoppaPoly()
    {
        return new PolynomialGF2mSmallM(this.getField(), encGp);
    }

    public Permutation getP()
    {
        return new Permutation(encP);
    }

    public GF2Matrix getH()
    {
        return new GF2Matrix(encH);
    }

    public PolynomialGF2mSmallM[] getQInv()
    {
        PolynomialGF2mSmallM[] qInv = new PolynomialGF2mSmallM[encqInv.length];
        GF2mField field = this.getField();

        for (int i = 0; i < encqInv.length; i++)
        {
            qInv[i] = new PolynomialGF2mSmallM(field, encqInv[i]);
        }

        return qInv;
    }

    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector v = new ASN1EncodableVector();
        // encode <oidString>
        v.add(oid);
        // encode <n>
        v.add(new ASN1Integer(n));

        // encode <k>
        v.add(new ASN1Integer(k));

        // encode <field>
        v.add(new DEROctetString(encField));

        // encode <gp>
        v.add(new DEROctetString(encGp));

        // encode <p>
        v.add(new DEROctetString(encP));

        // encode <h>
        v.add(new DEROctetString(encH));

        // encode <q>
        ASN1EncodableVector asnQInv = new ASN1EncodableVector();
        for (int i = 0; i < encqInv.length; i++)
        {
            asnQInv.add(new DEROctetString(encqInv[i]));
        }

        v.add(new DERSequence(asnQInv));

        return new DERSequence(v);
    }

    public static McElieceCCA2PrivateKey getInstance(Object o)
    {
        if (o instanceof McElieceCCA2PrivateKey)
        {
            return (McElieceCCA2PrivateKey)o;
        }
        else if (o != null)
        {
            return new McElieceCCA2PrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
