package org.bouncycastle.asn1.ua;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

public class DSTU4145Params
    extends ASN1Object
{
    private static final byte DEFAULT_DKE[] = {
        (byte)0xa9, (byte)0xd6, (byte)0xeb, 0x45, (byte)0xf1, 0x3c, 0x70, (byte)0x82,
        (byte)0x80, (byte)0xc4, (byte)0x96, 0x7b, 0x23, 0x1f, 0x5e, (byte)0xad,
        (byte)0xf6, 0x58, (byte)0xeb, (byte)0xa4, (byte)0xc0, 0x37, 0x29, 0x1d,
        0x38, (byte)0xd9, 0x6b, (byte)0xf0, 0x25, (byte)0xca, 0x4e, 0x17,
        (byte)0xf8, (byte)0xe9, 0x72, 0x0d, (byte)0xc6, 0x15, (byte)0xb4, 0x3a,
        0x28, (byte)0x97, 0x5f, 0x0b, (byte)0xc1, (byte)0xde, (byte)0xa3, 0x64,
        0x38, (byte)0xb5, 0x64, (byte)0xea, 0x2c, 0x17, (byte)0x9f, (byte)0xd0,
        0x12, 0x3e, 0x6d, (byte)0xb8, (byte)0xfa, (byte)0xc5, 0x79, 0x04};


    private ASN1ObjectIdentifier namedCurve;
    private DSTU4145ECBinary ecbinary;
    private byte[] dke = DEFAULT_DKE;

    public DSTU4145Params(ASN1ObjectIdentifier namedCurve)
    {
        this.namedCurve = namedCurve;
    }

    public DSTU4145Params(DSTU4145ECBinary ecbinary)
    {
        this.ecbinary = ecbinary;
    }

    public boolean isNamedCurve()
    {
        return namedCurve != null;
    }

    public DSTU4145ECBinary getECBinary()
    {
        return ecbinary;
    }

    public byte[] getDKE()
    {
        return dke;
    }

    public static byte[] getDefaultDKE()
    {
        return DEFAULT_DKE;
    }

    public ASN1ObjectIdentifier getNamedCurve()
    {
        return namedCurve;
    }

    public static DSTU4145Params getInstance(Object obj)
    {
        if (obj instanceof DSTU4145Params)
        {
            return (DSTU4145Params)obj;
        }

        if (obj != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(obj);
            DSTU4145Params params;

            if (seq.getObjectAt(0) instanceof ASN1ObjectIdentifier)
            {
                params = new DSTU4145Params(ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)));
            }
            else
            {
                params = new DSTU4145Params(DSTU4145ECBinary.getInstance(seq.getObjectAt(0)));
            }

            if (seq.size() == 2)
            {
                params.dke = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
                if (params.dke.length != DSTU4145Params.DEFAULT_DKE.length)
                {
                    throw new IllegalArgumentException("object parse error");
                }
            }

            return params;
        }

        throw new IllegalArgumentException("object parse error");
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (namedCurve != null)
        {
            v.add(namedCurve);
        }
        else
        {
            v.add(ecbinary);
        }

        if (!org.bouncycastle.util.Arrays.areEqual(dke, DEFAULT_DKE))
        {
            v.add(new DEROctetString(dke));
        }

        return new DERSequence(v);
    }
}
