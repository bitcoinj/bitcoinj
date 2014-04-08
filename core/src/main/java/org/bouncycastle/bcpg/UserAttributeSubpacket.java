package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Basic type for a user attribute sub-packet.
 */
public class UserAttributeSubpacket 
{
    int                type;
    
    protected byte[]   data;
    
    protected UserAttributeSubpacket(
        int            type,
        byte[]         data)
    {    
        this.type = type;
        this.data = data;
    }
    
    public int getType()
    {
        return type;
    }
    
    /**
     * return the generic data making up the packet.
     */
    public byte[] getData()
    {
        return data;
    }

    public void encode(
        OutputStream    out)
        throws IOException
    {
        int    bodyLen = data.length + 1;
        
        if (bodyLen < 192)
        {
            out.write((byte)bodyLen);
        }
        else if (bodyLen <= 8383)
        {
            bodyLen -= 192;
            
            out.write((byte)(((bodyLen >> 8) & 0xff) + 192));
            out.write((byte)bodyLen);
        }
        else
        {
            out.write(0xff);
            out.write((byte)(bodyLen >> 24));
            out.write((byte)(bodyLen >> 16));
            out.write((byte)(bodyLen >> 8));
            out.write((byte)bodyLen);
        }

        out.write(type);        
        out.write(data);
    }

    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof UserAttributeSubpacket))
        {
            return false;
        }

        UserAttributeSubpacket other = (UserAttributeSubpacket)o;

        return this.type == other.type
            && Arrays.areEqual(this.data, other.data);
    }

    public int hashCode()
    {
        return type ^ Arrays.hashCode(data);
    }
}
