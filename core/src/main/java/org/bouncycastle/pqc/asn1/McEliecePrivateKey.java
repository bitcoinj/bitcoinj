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

public class McEliecePrivateKey
    extends ASN1Object
{
    private ASN1ObjectIdentifier oid;
    private int n;
    private int k;
    private byte[] encField;
    private byte[] encGp;
    private byte[] encSInv;
    private byte[] encP1;
    private byte[] encP2;
    private byte[] encH;
    private byte[][] encqInv;


    public McEliecePrivateKey(ASN1ObjectIdentifier oid, int n, int k, GF2mField field, PolynomialGF2mSmallM goppaPoly, GF2Matrix sInv, Permutation p1, Permutation p2, GF2Matrix h, PolynomialGF2mSmallM[] qInv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        this.encField = field.getEncoded();
        this.encGp = goppaPoly.getEncoded();
        this.encSInv = sInv.getEncoded();
        this.encP1 = p1.getEncoded();
        this.encP2 = p2.getEncoded();
        this.encH = h.getEncoded();
        this.encqInv = new byte[qInv.length][];

        for (int i = 0; i != qInv.length; i++)
        {
            encqInv[i] = qInv[i].getEncoded();
        }
    }

    public static McEliecePrivateKey getInstance(Object o)
    {
        if (o instanceof McEliecePrivateKey)
        {
            return (McEliecePrivateKey)o;
        }
        else if (o != null)
        {
            return new McEliecePrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private McEliecePrivateKey(ASN1Sequence seq)
    {
        // <oidString>
        oid = ((ASN1ObjectIdentifier)seq.getObjectAt(0));

        BigInteger bigN = ((ASN1Integer)seq.getObjectAt(1)).getValue();
        n = bigN.intValue();

        BigInteger bigK = ((ASN1Integer)seq.getObjectAt(2)).getValue();
        k = bigK.intValue();

        encField = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();

        encGp = ((ASN1OctetString)seq.getObjectAt(4)).getOctets();

        encSInv = ((ASN1OctetString)seq.getObjectAt(5)).getOctets();

        encP1 = ((ASN1OctetString)seq.getObjectAt(6)).getOctets();

        encP2 = ((ASN1OctetString)seq.getObjectAt(7)).getOctets();

        encH = ((ASN1OctetString)seq.getObjectAt(8)).getOctets();

        ASN1Sequence asnQInv = (ASN1Sequence)seq.getObjectAt(9);
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

    public GF2Matrix getSInv()
    {
        return new GF2Matrix(encSInv);
    }

    public Permutation getP1()
    {
        return new Permutation(encP1);
    }

    public Permutation getP2()
    {
        return new Permutation(encP2);
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

        // encode <fieldPoly>
        v.add(new DEROctetString(encField));

        // encode <goppaPoly>
        v.add(new DEROctetString(encGp));

        // encode <sInv>
        v.add(new DEROctetString(encSInv));

        // encode <p1>
        v.add(new DEROctetString(encP1));

        // encode <p2>
        v.add(new DEROctetString(encP2));

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
}
