package com.google.bitcoin.bouncycastle.asn1.x9;

import java.math.BigInteger;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1OctetString;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERBitString;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERObjectIdentifier;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.math.ec.ECCurve;

/**
 * ASN.1 def for Elliptic-Curve Curve structure. See
 * X9.62, for further details.
 */
public class X9Curve
    extends ASN1Encodable
    implements X9ObjectIdentifiers
{
    private ECCurve     curve;
    private byte[]      seed;
    private DERObjectIdentifier fieldIdentifier = null;

    public X9Curve(
        ECCurve     curve)
    {
        this.curve = curve;
        this.seed = null;
        setFieldIdentifier();
    }

    public X9Curve(
        ECCurve     curve,
        byte[]      seed)
    {
        this.curve = curve;
        this.seed = seed;
        setFieldIdentifier();
    }

    public X9Curve(
        X9FieldID     fieldID,
        ASN1Sequence  seq)
    {
        fieldIdentifier = fieldID.getIdentifier();
        if (fieldIdentifier.equals(prime_field))
        {
            BigInteger      p = ((DERInteger)fieldID.getParameters()).getValue();
            X9FieldElement  x9A = new X9FieldElement(p, (ASN1OctetString)seq.getObjectAt(0));
            X9FieldElement  x9B = new X9FieldElement(p, (ASN1OctetString)seq.getObjectAt(1));
            curve = new ECCurve.Fp(p, x9A.getValue().toBigInteger(), x9B.getValue().toBigInteger());
        }
        else
        {
            if (fieldIdentifier.equals(characteristic_two_field)) 
            {
                // Characteristic two field
                DERSequence parameters = (DERSequence)fieldID.getParameters();
                int m = ((DERInteger)parameters.getObjectAt(0)).getValue().
                    intValue();
                DERObjectIdentifier representation
                    = (DERObjectIdentifier)parameters.getObjectAt(1);

                int k1 = 0;
                int k2 = 0;
                int k3 = 0;
                if (representation.equals(tpBasis)) 
                {
                    // Trinomial basis representation
                    k1 = ((DERInteger)parameters.getObjectAt(2)).getValue().
                        intValue();
                }
                else 
                {
                    // Pentanomial basis representation
                    DERSequence pentanomial
                        = (DERSequence)parameters.getObjectAt(2);
                    k1 = ((DERInteger)pentanomial.getObjectAt(0)).getValue().
                        intValue();
                    k2 = ((DERInteger)pentanomial.getObjectAt(1)).getValue().
                        intValue();
                    k3 = ((DERInteger)pentanomial.getObjectAt(2)).getValue().
                        intValue();
                }
                X9FieldElement x9A = new X9FieldElement(m, k1, k2, k3, (ASN1OctetString)seq.getObjectAt(0));
                X9FieldElement x9B = new X9FieldElement(m, k1, k2, k3, (ASN1OctetString)seq.getObjectAt(1));
                // TODO Is it possible to get the order (n) and cofactor(h) too?
                curve = new ECCurve.F2m(m, k1, k2, k3, x9A.getValue().toBigInteger(), x9B.getValue().toBigInteger());
            }
        }

        if (seq.size() == 3)
        {
            seed = ((DERBitString)seq.getObjectAt(2)).getBytes();
        }
    }

    private void setFieldIdentifier()
    {
        if (curve instanceof ECCurve.Fp)
        {
            fieldIdentifier = prime_field;
        }
        else if (curve instanceof ECCurve.F2m)
        {
            fieldIdentifier = characteristic_two_field;
        }
        else
        {
            throw new IllegalArgumentException("This type of ECCurve is not "
                    + "implemented");
        }
    }

    public ECCurve  getCurve()
    {
        return curve;
    }

    public byte[]   getSeed()
    {
        return seed;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  Curve ::= SEQUENCE {
     *      a               FieldElement,
     *      b               FieldElement,
     *      seed            BIT STRING      OPTIONAL
     *  }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (fieldIdentifier.equals(prime_field)) 
        { 
            v.add(new X9FieldElement(curve.getA()).getDERObject());
            v.add(new X9FieldElement(curve.getB()).getDERObject());
        } 
        else if (fieldIdentifier.equals(characteristic_two_field)) 
        {
            v.add(new X9FieldElement(curve.getA()).getDERObject());
            v.add(new X9FieldElement(curve.getB()).getDERObject());
        }

        if (seed != null)
        {
            v.add(new DERBitString(seed));
        }

        return new DERSequence(v);
    }
}
