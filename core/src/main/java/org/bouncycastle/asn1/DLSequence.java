package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

/**
 * The DLSequence encodes a SEQUENCE using definite length form.
 */
public class DLSequence
    extends ASN1Sequence
{
    private int bodyLength = -1;

    /**
     * Create an empty sequence
     */
    public DLSequence()
    {
    }

    /**
     * Create a sequence containing one object
     */
    public DLSequence(
        ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * Create a sequence containing a vector of objects.
     */
    public DLSequence(
        ASN1EncodableVector v)
    {
        super(v);
    }

    /**
     * Create a sequence containing an array of objects.
     */
    public DLSequence(
        ASN1Encodable[] array)
    {
        super(array);
    }

    private int getBodyLength()
        throws IOException
    {
        if (bodyLength < 0)
        {
            int length = 0;

            for (Enumeration e = this.getObjects(); e.hasMoreElements();)
            {
                Object obj = e.nextElement();

                length += ((ASN1Encodable)obj).toASN1Primitive().toDLObject().encodedLength();
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

    /**
     * A note on the implementation:
     * <p>
     * As DL requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SEQUENCE,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        ASN1OutputStream dOut = out.getDLSubStream();
        int length = getBodyLength();

        out.write(BERTags.SEQUENCE | BERTags.CONSTRUCTED);
        out.writeLength(length);

        for (Enumeration e = this.getObjects(); e.hasMoreElements();)
        {
            Object obj = e.nextElement();

            dOut.writeObject((ASN1Encodable)obj);
        }
    }
}