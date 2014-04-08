package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * DER NumericString object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
 */
public class DERNumericString
    extends ASN1Primitive
    implements ASN1String
{
    private byte[]  string;

    /**
     * return a Numeric string from the passed in object
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERNumericString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERNumericString)
        {
            return (DERNumericString)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERNumericString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Numeric String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERNumericString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERNumericString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERNumericString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - with bytes.
     */
    DERNumericString(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * basic constructor -  without validation..
     */
    public DERNumericString(
        String   string)
    {
        this(string, false);
    }

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in a NumericString.
     */
    public DERNumericString(
        String   string,
        boolean  validate)
    {
        if (validate && !isNumericString(string))
        {
            throw new IllegalArgumentException("string contains illegal characters");
        }

        this.string = Strings.toByteArray(string);
    }

    public String getString()
    {
        return Strings.fromByteArray(string);
    }

    public String toString()
    {
        return getString();
    }

    public byte[] getOctets()
    {
        return Arrays.clone(string);
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
        out.writeEncoded(BERTags.NUMERIC_STRING, string);
    }

    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERNumericString))
        {
            return false;
        }

        DERNumericString  s = (DERNumericString)o;

        return Arrays.areEqual(string, s.string);
    }

    /**
     * Return true if the string can be represented as a NumericString ('0'..'9', ' ')
     *
     * @param str string to validate.
     * @return true if numeric, fale otherwise.
     */
    public static boolean isNumericString(
        String  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            char    ch = str.charAt(i);

            if (ch > 0x007f)
            {
                return false;
            }

            if (('0' <= ch && ch <= '9') || ch == ' ')
            {
                continue;
            }

            return false;
        }

        return true;
    }
}
