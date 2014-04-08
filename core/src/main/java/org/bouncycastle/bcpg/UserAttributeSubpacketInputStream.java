package org.bouncycastle.bcpg;

import java.io.*;

import org.bouncycastle.bcpg.attr.ImageAttribute;

/**
 * reader for user attribute sub-packets
 */
public class UserAttributeSubpacketInputStream
    extends InputStream implements UserAttributeSubpacketTags
{
    InputStream    in;
    
    public UserAttributeSubpacketInputStream(
        InputStream    in)
    {
        this.in = in;
    }
    
    public int available()
        throws IOException
    {
        return in.available();
    }
    
    public int read()
        throws IOException
    {
        return in.read();
    }
    
    private void readFully(
        byte[]    buf,
        int       off,
        int       len)
        throws IOException
    {
        if (len > 0)
        {
            int    b = this.read();
            
            if (b < 0)
            {
                throw new EOFException();
            }
            
            buf[off] = (byte)b;
            off++;
            len--;
        }
        
        while (len > 0)
        {
            int    l = in.read(buf, off, len);
            
            if (l < 0)
            {
                throw new EOFException();
            }
            
            off += l;
            len -= l;
        }
    }
    
    public UserAttributeSubpacket readPacket()
        throws IOException
    {
        int            l = this.read();
        int            bodyLen = 0;
        
        if (l < 0)
        {
            return null;
        }

        if (l < 192)
        {
            bodyLen = l;
        }
        else if (l <= 223)
        {
            bodyLen = ((l - 192) << 8) + (in.read()) + 192;
        }
        else if (l == 255)
        {
            bodyLen = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
        }
        else
        {
            // TODO Error?
        }

       int        tag = in.read();

       if (tag < 0)
       {
               throw new EOFException("unexpected EOF reading user attribute sub packet");
       }
       
       byte[]    data = new byte[bodyLen - 1];

       this.readFully(data, 0, data.length);
       
       int       type = tag;

       switch (type)
       {
       case IMAGE_ATTRIBUTE:
           return new ImageAttribute(data);
       }

       return new UserAttributeSubpacket(type, data);
    }
}
