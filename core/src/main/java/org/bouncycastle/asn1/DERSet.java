package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

/**
 * A DER encoded set object
 */
public class DERSet
    extends ASN1Set
{
    private int bodyLength = -1;

    /**
     * create an empty set
     */
    public DERSet()
    {
    }

    /**
     * @param obj - a single object that makes up the set.
     */
    public DERSet(
        ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * @param v - a vector of objects making up the set.
     */
    public DERSet(
        ASN1EncodableVector v)
    {
        super(v, true);
    }
    
    /**
     * create a set from an array of objects.
     */
    public DERSet(
        ASN1Encodable[]   a)
    {
        super(a, true);
    }

    DERSet(
        ASN1EncodableVector v,
        boolean                  doSort)
    {
        super(v, doSort);
    }

    private int getBodyLength()
        throws IOException
    {
        if (bodyLength < 0)
        {
            int length = 0;

            for (Enumeration e = this.getObjects(); e.hasMoreElements();)
            {
                Object    obj = e.nextElement();

                length += ((ASN1Encodable)obj).toASN1Primitive().toDERObject().encodedLength();
            }

            bodyLength = length;
        }

        return bodyLength;
    }

    int encodedLength()
        throws IOException
    {
        int length = getBodyLength();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SET,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        ASN1OutputStream        dOut = out.getDERSubStream();
        int                     length = getBodyLength();

        out.write(BERTags.SET | BERTags.CONSTRUCTED);
        out.writeLength(length);

        for (Enumeration e = this.getObjects(); e.hasMoreElements();)
        {
            Object    obj = e.nextElement();

            dOut.writeObject((ASN1Encodable)obj);
        }
    }
}
