package org.bouncycastle.asn1.x9;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;

/**
 * ASN.1 def for Elliptic-Curve Curve structure. See
 * X9.62, for further details.
 */
public class X9Curve
    extends ASN1Object
    implements X9ObjectIdentifiers
{
    private ECCurve     curve;
    private byte[]      seed;
    private ASN1ObjectIdentifier fieldIdentifier = null;

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
        // TODO Is it possible to get the order(n) and cofactor(h) too?

        fieldIdentifier = fieldID.getIdentifier();
        if (fieldIdentifier.equals(prime_field))
        {
            BigInteger      p = ((ASN1Integer)fieldID.getParameters()).getValue();
            X9FieldElement  x9A = new X9FieldElement(p, (ASN1OctetString)seq.getObjectAt(0));
            X9FieldElement  x9B = new X9FieldElement(p, (ASN1OctetString)seq.getObjectAt(1));
            curve = new ECCurve.Fp(p, x9A.getValue().toBigInteger(), x9B.getValue().toBigInteger());
        }
        else if (fieldIdentifier.equals(characteristic_two_field)) 
        {
            // Characteristic two field
            ASN1Sequence parameters = ASN1Sequence.getInstance(fieldID.getParameters());
            int m = ((ASN1Integer)parameters.getObjectAt(0)).getValue().
                intValue();
            ASN1ObjectIdentifier representation
                = (ASN1ObjectIdentifier)parameters.getObjectAt(1);

            int k1 = 0;
            int k2 = 0;
            int k3 = 0;

            if (representation.equals(tpBasis)) 
            {
                // Trinomial basis representation
                k1 = ASN1Integer.getInstance(parameters.getObjectAt(2)).getValue().intValue();
            }
            else if (representation.equals(ppBasis))
            {
                // Pentanomial basis representation
                ASN1Sequence pentanomial = ASN1Sequence.getInstance(parameters.getObjectAt(2));
                k1 = ASN1Integer.getInstance(pentanomial.getObjectAt(0)).getValue().intValue();
                k2 = ASN1Integer.getInstance(pentanomial.getObjectAt(1)).getValue().intValue();
                k3 = ASN1Integer.getInstance(pentanomial.getObjectAt(2)).getValue().intValue();
            }
            else
            {
                throw new IllegalArgumentException("This type of EC basis is not implemented");
            }
            X9FieldElement x9A = new X9FieldElement(m, k1, k2, k3, (ASN1OctetString)seq.getObjectAt(0));
            X9FieldElement x9B = new X9FieldElement(m, k1, k2, k3, (ASN1OctetString)seq.getObjectAt(1));
            curve = new ECCurve.F2m(m, k1, k2, k3, x9A.getValue().toBigInteger(), x9B.getValue().toBigInteger());
        }
        else
        {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        }

        if (seq.size() == 3)
        {
            seed = ((DERBitString)seq.getObjectAt(2)).getBytes();
        }
    }

    private void setFieldIdentifier()
    {
        if (ECAlgorithms.isFpCurve(curve))
        {
            fieldIdentifier = prime_field;
        }
        else if (ECAlgorithms.isF2mCurve(curve))
        {
            fieldIdentifier = characteristic_two_field;
        }
        else
        {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
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
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (fieldIdentifier.equals(prime_field)) 
        { 
            v.add(new X9FieldElement(curve.getA()).toASN1Primitive());
            v.add(new X9FieldElement(curve.getB()).toASN1Primitive());
        } 
        else if (fieldIdentifier.equals(characteristic_two_field)) 
        {
            v.add(new X9FieldElement(curve.getA()).toASN1Primitive());
            v.add(new X9FieldElement(curve.getB()).toASN1Primitive());
        }

        if (seed != null)
        {
            v.add(new DERBitString(seed));
        }

        return new DERSequence(v);
    }
}
