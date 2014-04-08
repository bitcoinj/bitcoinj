package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * DER T61String (also the teletex string) - a "modern" encapsulation that uses UTF-8. If at all possible, avoid this one! It's only for emergencies.
 * Use UTF8String instead.
 */
public class DERT61UTF8String
    extends ASN1Primitive
    implements ASN1String
{
    private byte[] string;

    /**
     * return a T61 string from the passed in object. UTF-8 Encoding is assumed in this case.
     *
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static DERT61UTF8String getInstance(
        Object obj)
    {
        if (obj instanceof DERT61String)
        {
            return new DERT61UTF8String(((DERT61String)obj).getOctets());
        }

        if (obj == null || obj instanceof DERT61UTF8String)
        {
            return (DERT61UTF8String)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return new DERT61UTF8String(((DERT61String)fromByteArray((byte[])obj)).getOctets());
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an T61 String from a tagged object. UTF-8 encoding is assumed in this case.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws IllegalArgumentException if the tagged object cannot
     * be converted.
     */
    public static DERT61UTF8String getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERT61String || o instanceof DERT61UTF8String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERT61UTF8String(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - string encoded as a sequence of bytes.
     */
    public DERT61UTF8String(
        byte[] string)
    {
        this.string = string;
    }

    /**
     * basic constructor - with string UTF8 conversion assumed.
     */
    public DERT61UTF8String(
        String string)
    {
        this(Strings.toUTF8ByteArray(string));
    }

    /**
     * Decode the encoded string and return it, UTF8 assumed.
     *
     * @return the decoded String
     */
    public String getString()
    {
        return Strings.fromUTF8ByteArray(string);
    }

    public String toString()
    {
        return getString();
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.T61_STRING, string);
    }

    /**
     * Return the encoded string as a byte array.
     *
     * @return the actual bytes making up the encoded body of the T61 string.
     */
    public byte[] getOctets()
    {
        return Arrays.clone(string);
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERT61UTF8String))
        {
            return false;
        }

        return Arrays.areEqual(string, ((DERT61UTF8String)o).string);
    }

    public int hashCode()
    {
        return Arrays.hashCode(string);
    }
}
