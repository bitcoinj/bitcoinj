package com.google.bitcoin.bouncycastle.asn1.x509;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;

public class GeneralNames
    extends ASN1Encodable
{
    private final GeneralName[] names;

    public static GeneralNames getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof GeneralNames)
        {
            return (GeneralNames)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new GeneralNames((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static GeneralNames getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Construct a GeneralNames object containing one GeneralName.
     * 
     * @param name the name to be contained.
     */
    public GeneralNames(
        GeneralName  name)
    {
        this.names = new GeneralName[] { name };
    }
    
    public GeneralNames(
        ASN1Sequence  seq)
    {
        this.names = new GeneralName[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            names[i] = GeneralName.getInstance(seq.getObjectAt(i));
        }
    }

    public GeneralName[] getNames()
    {
        GeneralName[] tmp = new GeneralName[names.length];

        System.arraycopy(names, 0, tmp, 0, names.length);

        return tmp;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * GeneralNames ::= SEQUENCE SIZE {1..MAX} OF GeneralName
     * </pre>
     */
    public DERObject toASN1Object()
    {
        return new DERSequence(names);
    }

    public String toString()
    {
        StringBuffer  buf = new StringBuffer();
        String        sep = System.getProperty("line.separator");

        buf.append("GeneralNames:");
        buf.append(sep);

        for (int i = 0; i != names.length; i++)
        {
            buf.append("    ");
            buf.append(names[i]);
            buf.append(sep);
        }
        return buf.toString();
    }
}
