package org.bouncycastle.asn1.tsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;


public class Accuracy
    extends ASN1Object
{
    ASN1Integer seconds;

    ASN1Integer millis;

    ASN1Integer micros;

    // constantes
    protected static final int MIN_MILLIS = 1;

    protected static final int MAX_MILLIS = 999;

    protected static final int MIN_MICROS = 1;

    protected static final int MAX_MICROS = 999;

    protected Accuracy()
    {
    }

    public Accuracy(
        ASN1Integer seconds,
        ASN1Integer millis,
        ASN1Integer micros)
    {
        this.seconds = seconds;

        //Verifications
        if (millis != null
                && (millis.getValue().intValue() < MIN_MILLIS || millis
                        .getValue().intValue() > MAX_MILLIS))
        {
            throw new IllegalArgumentException(
                    "Invalid millis field : not in (1..999)");
        }
        else
        {
            this.millis = millis;
        }

        if (micros != null
                && (micros.getValue().intValue() < MIN_MICROS || micros
                        .getValue().intValue() > MAX_MICROS))
        {
            throw new IllegalArgumentException(
                    "Invalid micros field : not in (1..999)");
        }
        else
        {
            this.micros = micros;
        }

    }

    private Accuracy(ASN1Sequence seq)
    {
        seconds = null;
        millis = null;
        micros = null;

        for (int i = 0; i < seq.size(); i++)
        {
            // seconds
            if (seq.getObjectAt(i) instanceof ASN1Integer)
            {
                seconds = (ASN1Integer) seq.getObjectAt(i);
            }
            else if (seq.getObjectAt(i) instanceof DERTaggedObject)
            {
                DERTaggedObject extra = (DERTaggedObject) seq.getObjectAt(i);

                switch (extra.getTagNo())
                {
                case 0:
                    millis = ASN1Integer.getInstance(extra, false);
                    if (millis.getValue().intValue() < MIN_MILLIS
                            || millis.getValue().intValue() > MAX_MILLIS)
                    {
                        throw new IllegalArgumentException(
                                "Invalid millis field : not in (1..999).");
                    }
                    break;
                case 1:
                    micros = ASN1Integer.getInstance(extra, false);
                    if (micros.getValue().intValue() < MIN_MICROS
                            || micros.getValue().intValue() > MAX_MICROS)
                    {
                        throw new IllegalArgumentException(
                                "Invalid micros field : not in (1..999).");
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Invalig tag number");
                }
            }
        }
    }

    public static Accuracy getInstance(Object o)
    {
        if (o instanceof Accuracy)
        {
            return (Accuracy) o;
        }

        if (o != null)
        {
            return new Accuracy(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Integer getSeconds()
    {
        return seconds;
    }

    public ASN1Integer getMillis()
    {
        return millis;
    }

    public ASN1Integer getMicros()
    {
        return micros;
    }

    /**
     * <pre>
     * Accuracy ::= SEQUENCE {
     *             seconds        INTEGER              OPTIONAL,
     *             millis     [0] INTEGER  (1..999)    OPTIONAL,
     *             micros     [1] INTEGER  (1..999)    OPTIONAL
     *             }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector v = new ASN1EncodableVector();
        
        if (seconds != null)
        {
            v.add(seconds);
        }
        
        if (millis != null)
        {
            v.add(new DERTaggedObject(false, 0, millis));
        }
        
        if (micros != null)
        {
            v.add(new DERTaggedObject(false, 1, micros));
        }

        return new DERSequence(v);
    }
}
