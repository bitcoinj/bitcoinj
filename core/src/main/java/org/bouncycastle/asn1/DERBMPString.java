package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * DER BMPString object.
 */
public class DERBMPString
    extends ASN1Primitive
    implements ASN1String
{
    private char[]  string;

    /**
     * return a BMP String from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERBMPString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERBMPString)
        {
            return (DERBMPString)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERBMPString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a BMP String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *              be converted.
     */
    public static DERBMPString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBMPString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERBMPString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     */
    DERBMPString(
        byte[]   string)
    {
        char[]  cs = new char[string.length / 2];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)((string[2 * i] << 8) | (string[2 * i + 1] & 0xff));
        }

        this.string = cs;
    }

    DERBMPString(char[] string)
    {
        this.string = string;
    }

    /**
     * basic constructor
     */
    public DERBMPString(
        String   string)
    {
        this.string = string.toCharArray();
    }

    public String getString()
    {
        return new String(string);
    }

    public String toString()
    {
        return getString();
    }

    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    protected boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERBMPString))
        {
            return false;
        }

        DERBMPString  s = (DERBMPString)o;

        return Arrays.areEqual(string, s.string);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length * 2) + (string.length * 2);
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.write(BERTags.BMP_STRING);
        out.writeLength(string.length * 2);

        for (int i = 0; i != string.length; i++)
        {
            char c = string[i];

            out.write((byte)(c >> 8));
            out.write((byte)c);
        }
    }
}
