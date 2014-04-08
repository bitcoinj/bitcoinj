package org.bouncycastle.asn1.ua;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.util.Arrays;

public class DSTU4145ECBinary
    extends ASN1Object
{
    BigInteger version = BigInteger.valueOf(0);

    DSTU4145BinaryField f;
    ASN1Integer a;
    ASN1OctetString b;
    ASN1Integer n;
    ASN1OctetString bp;

    public DSTU4145ECBinary(ECDomainParameters params)
    {
        ECCurve curve = params.getCurve();
        if (!ECAlgorithms.isF2mCurve(curve))
        {
            throw new IllegalArgumentException("only binary domain is possible");
        }

        // We always use big-endian in parameter encoding

        PolynomialExtensionField field = (PolynomialExtensionField)curve.getField();
        int[] exponents = field.getMinimalPolynomial().getExponentsPresent();
        if (exponents.length == 3)
        {
            f = new DSTU4145BinaryField(exponents[2], exponents[1]);
        }
        else if (exponents.length == 5)
        {
            f = new DSTU4145BinaryField(exponents[4], exponents[1], exponents[2], exponents[3]);
        }

        a = new ASN1Integer(curve.getA().toBigInteger());
        b = new DEROctetString(curve.getB().getEncoded());
        n = new ASN1Integer(params.getN());
        bp = new DEROctetString(DSTU4145PointEncoder.encodePoint(params.getG()));
    }

    private DSTU4145ECBinary(ASN1Sequence seq)
    {
        int index = 0;

        if (seq.getObjectAt(index) instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject taggedVersion = (ASN1TaggedObject)seq.getObjectAt(index);
            if (taggedVersion.isExplicit() && 0 == taggedVersion.getTagNo())
            {
                version = ASN1Integer.getInstance(taggedVersion.getLoadedObject()).getValue();
                index++;
            }
            else
            {
                throw new IllegalArgumentException("object parse error");
            }
        }
        f = DSTU4145BinaryField.getInstance(seq.getObjectAt(index));
        index++;
        a = ASN1Integer.getInstance(seq.getObjectAt(index));
        index++;
        b = ASN1OctetString.getInstance(seq.getObjectAt(index));
        index++;
        n = ASN1Integer.getInstance(seq.getObjectAt(index));
        index++;
        bp = ASN1OctetString.getInstance(seq.getObjectAt(index));
    }

    public static DSTU4145ECBinary getInstance(Object obj)
    {
        if (obj instanceof DSTU4145ECBinary)
        {
            return (DSTU4145ECBinary)obj;
        }

        if (obj != null)
        {
            return new DSTU4145ECBinary(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public DSTU4145BinaryField getField()
    {
        return f;
    }

    public BigInteger getA()
    {
        return a.getValue();
    }

    public byte[] getB()
    {
        return Arrays.clone(b.getOctets());
    }

    public BigInteger getN()
    {
        return n.getValue();
    }

    public byte[] getG()
    {
        return Arrays.clone(bp.getOctets());
    }

    /**
     * ECBinary  ::= SEQUENCE {
     * version          [0] EXPLICIT INTEGER    DEFAULT 0,
     * f     BinaryField,
     * a    INTEGER (0..1),
     * b    OCTET STRING,
     * n    INTEGER,
     * bp    OCTET STRING}
     */
    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector v = new ASN1EncodableVector();

        if (0 != version.compareTo(BigInteger.valueOf(0)))
        {
            v.add(new DERTaggedObject(true, 0, new ASN1Integer(version)));
        }
        v.add(f);
        v.add(a);
        v.add(b);
        v.add(n);
        v.add(bp);

        return new DERSequence(v);
    }

}
