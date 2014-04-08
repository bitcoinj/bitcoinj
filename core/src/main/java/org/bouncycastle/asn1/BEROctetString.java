package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

public class BEROctetString
    extends ASN1OctetString
{
    private static final int MAX_LENGTH = 1000;

    private ASN1OctetString[] octs;

    /**
     * convert a vector of octet strings into a single byte string
     */
    static private byte[] toBytes(
        ASN1OctetString[]  octs)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        for (int i = 0; i != octs.length; i++)
        {
            try
            {
                DEROctetString o = (DEROctetString)octs[i];

                bOut.write(o.getOctets());
            }
            catch (ClassCastException e)
            {
                throw new IllegalArgumentException(octs[i].getClass().getName() + " found in input should only contain DEROctetString");
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("exception converting octets " + e.toString());
            }
        }

        return bOut.toByteArray();
    }

    /**
     * @param string the octets making up the octet string.
     */
    public BEROctetString(
        byte[] string)
    {
        super(string);
    }

    public BEROctetString(
        ASN1OctetString[] octs)
    {
        super(toBytes(octs));

        this.octs = octs;
    }

    public byte[] getOctets()
    {
        return string;
    }

    /**
     * return the DER octets that make up this string.
     */
    public Enumeration getObjects()
    {
        if (octs == null)
        {
            return generateOcts().elements();
        }

        return new Enumeration()
        {
            int counter = 0;

            public boolean hasMoreElements()
            {
                return counter < octs.length;
            }

            public Object nextElement()
            {
                return octs[counter++];
            }
        };
    }

    private Vector generateOcts()
    { 
        Vector vec = new Vector();
        for (int i = 0; i < string.length; i += MAX_LENGTH) 
        { 
            int end; 

            if (i + MAX_LENGTH > string.length) 
            { 
                end = string.length; 
            } 
            else 
            { 
                end = i + MAX_LENGTH; 
            } 

            byte[] nStr = new byte[end - i]; 

            System.arraycopy(string, i, nStr, 0, nStr.length);

            vec.addElement(new DEROctetString(nStr));
         } 
        
         return vec; 
    }

    boolean isConstructed()
    {
        return true;
    }

    int encodedLength()
        throws IOException
    {
        int length = 0;
        for (Enumeration e = getObjects(); e.hasMoreElements();)
        {
            length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
        }

        return 2 + length + 2;
    }

    public void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.write(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);

        out.write(0x80);

        //
        // write out the octet array
        //
        for (Enumeration e = getObjects(); e.hasMoreElements();)
        {
            out.writeObject((ASN1Encodable)e.nextElement());
        }

        out.write(0x00);
        out.write(0x00);
    }

    static BEROctetString fromSequence(ASN1Sequence seq)
    {
        ASN1OctetString[]     v = new ASN1OctetString[seq.size()];
        Enumeration e = seq.getObjects();
        int                   index = 0;

        while (e.hasMoreElements())
        {
            v[index++] = (ASN1OctetString)e.nextElement();
        }

        return new BEROctetString(v);
    }
}
