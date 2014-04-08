package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Base class for an application specific object
 */
public class DERApplicationSpecific 
    extends ASN1Primitive
{
    private final boolean   isConstructed;
    private final int       tag;
    private final byte[]    octets;

    DERApplicationSpecific(
        boolean isConstructed,
        int     tag,
        byte[]  octets)
    {
        this.isConstructed = isConstructed;
        this.tag = tag;
        this.octets = octets;
    }

    public DERApplicationSpecific(
        int    tag,
        byte[] octets)
    {
        this(false, tag, octets);
    }

    public DERApplicationSpecific(
        int                  tag, 
        ASN1Encodable object)
        throws IOException 
    {
        this(true, tag, object);
    }

    public DERApplicationSpecific(
        boolean      explicit,
        int          tag,
        ASN1Encodable object)
        throws IOException
    {
        ASN1Primitive primitive = object.toASN1Primitive();

        byte[] data = primitive.getEncoded(ASN1Encoding.DER);

        this.isConstructed = explicit || (primitive instanceof ASN1Set || primitive instanceof ASN1Sequence);
        this.tag = tag;

        if (explicit)
        {
            this.octets = data;
        }
        else
        {
            int lenBytes = getLengthOfHeader(data);
            byte[] tmp = new byte[data.length - lenBytes];
            System.arraycopy(data, lenBytes, tmp, 0, tmp.length);
            this.octets = tmp;
        }
    }

    public DERApplicationSpecific(int tagNo, ASN1EncodableVector vec)
    {
        this.tag = tagNo;
        this.isConstructed = true;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        for (int i = 0; i != vec.size(); i++)
        {
            try
            {
                bOut.write(((ASN1Object)vec.get(i)).getEncoded(ASN1Encoding.DER));
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("malformed object: " + e, e);
            }
        }
        this.octets = bOut.toByteArray();
    }

    public static DERApplicationSpecific getInstance(Object obj)
    {
        if (obj == null || obj instanceof DERApplicationSpecific)
        {
            return (DERApplicationSpecific)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return DERApplicationSpecific.getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct object from byte[]: " + e.getMessage());
            }
        }
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

            if (primitive instanceof ASN1Sequence)
            {
                return (DERApplicationSpecific)primitive;
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    private int getLengthOfHeader(byte[] data)
    {
        int length = data[1] & 0xff; // TODO: assumes 1 byte tag

        if (length == 0x80)
        {
            return 2;      // indefinite-length encoding
        }

        if (length > 127)
        {
            int size = length & 0x7f;

            // Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
            if (size > 4)
            {
                throw new IllegalStateException("DER length more than 4 bytes: " + size);
            }

            return size + 2;
        }

        return 2;
    }

    public boolean isConstructed()
    {
        return isConstructed;
    }
    
    public byte[] getContents()
    {
        return octets;
    }
    
    public int getApplicationTag() 
    {
        return tag;
    }

    /**
     * Return the enclosed object assuming explicit tagging.
     *
     * @return  the resulting object
     * @throws IOException if reconstruction fails.
     */
    public ASN1Primitive getObject()
        throws IOException 
    {
        return new ASN1InputStream(getContents()).readObject();
    }

    /**
     * Return the enclosed object assuming implicit tagging.
     *
     * @param derTagNo the type tag that should be applied to the object's contents.
     * @return  the resulting object
     * @throws IOException if reconstruction fails.
     */
    public ASN1Primitive getObject(int derTagNo)
        throws IOException
    {
        if (derTagNo >= 0x1f)
        {
            throw new IOException("unsupported tag number");
        }

        byte[] orig = this.getEncoded();
        byte[] tmp = replaceTagNumber(derTagNo, orig);

        if ((orig[0] & BERTags.CONSTRUCTED) != 0)
        {
            tmp[0] |= BERTags.CONSTRUCTED;
        }

        return new ASN1InputStream(tmp).readObject();
    }

    int encodedLength()
        throws IOException
    {
        return StreamUtil.calculateTagLength(tag) + StreamUtil.calculateBodyLength(octets.length) + octets.length;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.DEROutputStream)
     */
    void encode(ASN1OutputStream out) throws IOException
    {
        int classBits = BERTags.APPLICATION;
        if (isConstructed)
        {
            classBits |= BERTags.CONSTRUCTED;
        }

        out.writeEncoded(classBits, tag, octets);
    }
    
    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERApplicationSpecific))
        {
            return false;
        }

        DERApplicationSpecific other = (DERApplicationSpecific)o;

        return isConstructed == other.isConstructed
            && tag == other.tag
            && Arrays.areEqual(octets, other.octets);
    }

    public int hashCode()
    {
        return (isConstructed ? 1 : 0) ^ tag ^ Arrays.hashCode(octets);
    }

    private byte[] replaceTagNumber(int newTag, byte[] input)
        throws IOException
    {
        int tagNo = input[0] & 0x1f;
        int index = 1;
        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f)
        {
            tagNo = 0;

            int b = input[index++] & 0xff;

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) // Note: -1 will pass
            {
                throw new ASN1ParsingException("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0))
            {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = input[index++] & 0xff;
            }

            tagNo |= (b & 0x7f);
        }

        byte[] tmp = new byte[input.length - index + 1];

        System.arraycopy(input, index, tmp, 1, tmp.length - 1);

        tmp[0] = (byte)newTag;

        return tmp;
    }
}
