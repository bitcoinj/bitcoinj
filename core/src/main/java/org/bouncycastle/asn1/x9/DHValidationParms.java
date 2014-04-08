package org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

public class DHValidationParms extends ASN1Object
{
    private DERBitString seed;
    private ASN1Integer pgenCounter;

    public static DHValidationParms getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static DHValidationParms getInstance(Object obj)
    {
        if (obj == null || obj instanceof DHDomainParameters)
        {
            return (DHValidationParms)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new DHValidationParms((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("Invalid DHValidationParms: " + obj.getClass().getName());
    }

    public DHValidationParms(DERBitString seed, ASN1Integer pgenCounter)
    {
        if (seed == null)
        {
            throw new IllegalArgumentException("'seed' cannot be null");
        }
        if (pgenCounter == null)
        {
            throw new IllegalArgumentException("'pgenCounter' cannot be null");
        }

        this.seed = seed;
        this.pgenCounter = pgenCounter;
    }

    private DHValidationParms(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.seed = DERBitString.getInstance(seq.getObjectAt(0));
        this.pgenCounter = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public DERBitString getSeed()
    {
        return this.seed;
    }

    public ASN1Integer getPgenCounter()
    {
        return this.pgenCounter;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.seed);
        v.add(this.pgenCounter);
        return new DERSequence(v);
    }
}
