package org.bouncycastle.asn1;

import java.io.IOException;

public abstract class ASN1Primitive
    extends ASN1Object
{
    ASN1Primitive()
    {

    }

    /**
     * Create a base ASN.1 object from a byte stream.
     *
     * @param data the byte stream to parse.
     * @return the base ASN.1 object represented by the byte stream.
     * @exception IOException if there is a problem parsing the data.
     */
    public static ASN1Primitive fromByteArray(byte[] data)
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(data);

        try
        {
            return aIn.readObject();
        }
        catch (ClassCastException e)
        {
            throw new IOException("cannot recognise object in stream");
        }
    }

    public final boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        return (o instanceof ASN1Encodable) && asn1Equals(((ASN1Encodable)o).toASN1Primitive());
    }

    public ASN1Primitive toASN1Primitive()
    {
        return this;
    }

    ASN1Primitive toDERObject()
    {
        return this;
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }

    public abstract int hashCode();

    abstract boolean isConstructed();

    abstract int encodedLength() throws IOException;

    abstract void encode(ASN1OutputStream out) throws IOException;

    abstract boolean asn1Equals(ASN1Primitive o);
}