package org.bouncycastle.asn1.eac;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;


/**
 * an Iso7816RSAPublicKeyStructure structure.
 * <pre>
 *  Certificate Holder Authorization ::= SEQUENCE {
 *      // modulus should be at least 1024bit and a multiple of 512.
 *      DERTaggedObject        modulus,
 *      // access rights    exponent
 *      DERTaggedObject    accessRights,
 *  }
 * </pre>
 */
public class RSAPublicKey
    extends PublicKeyDataObject
{
    private ASN1ObjectIdentifier usage;
    private BigInteger modulus;
    private BigInteger exponent;
    private int valid = 0;
    private static int modulusValid = 0x01;
    private static int exponentValid = 0x02;

    RSAPublicKey(ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();

        this.usage = ASN1ObjectIdentifier.getInstance(en.nextElement());

        while (en.hasMoreElements())
        {
            UnsignedInteger val = UnsignedInteger.getInstance(en.nextElement());

            switch (val.getTagNo())
            {
            case 0x1:
                setModulus(val);
                break;
            case 0x2:
                setExponent(val);
                break;
            default:
                throw new IllegalArgumentException("Unknown DERTaggedObject :" + val.getTagNo() + "-> not an Iso7816RSAPublicKeyStructure");
            }
        }
        if (valid != 0x3)
        {
            throw new IllegalArgumentException("missing argument -> not an Iso7816RSAPublicKeyStructure");
        }
    }

    public RSAPublicKey(ASN1ObjectIdentifier usage, BigInteger modulus, BigInteger exponent)
    {
        this.usage = usage;
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public ASN1ObjectIdentifier getUsage()
    {
        return usage;
    }

    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getPublicExponent()
    {
        return exponent;
    }

    private void setModulus(UnsignedInteger modulus)
    {
        if ((valid & modulusValid) == 0)
        {
            valid |= modulusValid;
            this.modulus = modulus.getValue();
        }
        else
        {
            throw new IllegalArgumentException("Modulus already set");
        }
    }

    private void setExponent(UnsignedInteger exponent)
    {
        if ((valid & exponentValid) == 0)
        {
            valid |= exponentValid;
            this.exponent = exponent.getValue();
        }
        else
        {
            throw new IllegalArgumentException("Exponent already set");
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(usage);
        v.add(new UnsignedInteger(0x01, getModulus()));
        v.add(new UnsignedInteger(0x02, getPublicExponent()));

        return new DERSequence(v);
    }
}
