package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * DER IA5String object - this is an ascii string.
 */
public class DERIA5String
    extends ASN1Primitive
    implements ASN1String
{
    private byte[]  string;

    /**
     * return a IA5 string from the passed in object
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERIA5String getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERIA5String)
        {
            return (DERIA5String)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERIA5String)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an IA5 String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERIA5String getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERIA5String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERIA5String(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * basic constructor - with bytes.
     */
    DERIA5String(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * basic constructor - without validation.
     */
    public DERIA5String(
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
     * contains characters that should not be in an IA5String.
     */
    public DERIA5String(
        String   string,
        boolean  validate)
    {
        if (string == null)
        {
            throw new NullPointerException("string cannot be null");
        }
        if (validate && !isIA5String(string))
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
        out.writeEncoded(BERTags.IA5_STRING, string);
    }

    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERIA5String))
        {
            return false;
        }

        DERIA5String  s = (DERIA5String)o;

        return Arrays.areEqual(string, s.string);
    }

    /**
     * return true if the passed in String can be represented without
     * loss as an IA5String, false otherwise.
     *
     * @return true if in printable set, false otherwise.
     */
    public static boolean isIA5String(
        String  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            char    ch = str.charAt(i);

            if (ch > 0x007f)
            {
                return false;
            }
        }

        return true;
    }
}
