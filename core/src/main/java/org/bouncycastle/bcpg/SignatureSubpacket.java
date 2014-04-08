package org.bouncycastle.bcpg;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Basic type for a PGP Signature sub-packet.
 */
public class SignatureSubpacket 
{
    int               type;
    boolean           critical;
    
    protected byte[]  data;
    
    protected SignatureSubpacket(
        int           type,
        boolean       critical,
        byte[]        data)
    {    
        this.type = type;
        this.critical = critical;
        this.data = data;
    }
    
    public int getType()
    {
        return type;
    }
    
    public boolean isCritical()
    {
        return critical;
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
        
        if (critical)
        {
            out.write(0x80 | type);
        }
        else
        {
            out.write(type);
        }
        
        out.write(data);
    }
}
