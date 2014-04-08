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

public class McEliecePublicKey
    extends ASN1Object
{

    private ASN1ObjectIdentifier oid;
    private int n;
    private int t;

    private byte[] matrixG;

    public McEliecePublicKey(ASN1ObjectIdentifier oid, int n, int t, GF2Matrix g)
    {
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.matrixG = g.getEncoded();
    }

    private McEliecePublicKey(ASN1Sequence seq)
    {
        oid = ((ASN1ObjectIdentifier)seq.getObjectAt(0));
        BigInteger bigN = ((ASN1Integer)seq.getObjectAt(1)).getValue();
        n = bigN.intValue();

        BigInteger bigT = ((ASN1Integer)seq.getObjectAt(2)).getValue();
        t = bigT.intValue();

        matrixG = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();
    }

    public ASN1ObjectIdentifier getOID()
    {
        return oid;
    }

    public int getN()
    {
        return n;
    }

    public int getT()
    {
        return t;
    }

    public GF2Matrix getG()
    {
        return new GF2Matrix(matrixG);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        // encode <oidString>
        v.add(oid);

        // encode <n>
        v.add(new ASN1Integer(n));

        // encode <t>
        v.add(new ASN1Integer(t));

        // encode <matrixG>
        v.add(new DEROctetString(matrixG));

        return new DERSequence(v);
    }

    public static McEliecePublicKey getInstance(Object o)
    {
        if (o instanceof McEliecePublicKey)
        {
            return (McEliecePublicKey)o;
        }
        else if (o != null)
        {
            return new McEliecePublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
