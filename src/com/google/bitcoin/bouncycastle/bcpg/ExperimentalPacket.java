package com.google.bitcoin.bouncycastle.bcpg;

import java.io.*;

/**
 * basic packet for an experimental packet.
 */
public class ExperimentalPacket 
    extends ContainedPacket implements PublicKeyAlgorithmTags
{
    private int    tag;
    private byte[] contents;
    
    /**
     * 
     * @param in
     * @throws IOException
     */
    ExperimentalPacket(
        int                tag,
        BCPGInputStream    in)
        throws IOException
    {
        this.tag = tag;
        
        if (in.available() != 0)
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream(in.available());
            
            int b;
            while ((b = in.read()) >= 0) 
            {
                 bOut.write(b);
            }
            
            contents = bOut.toByteArray();
        }
        else
        {
            contents = new byte[0];
        }
    }
    
    public int getTag()
    {
        return tag;
    }
    
    public byte[] getContents()
    {
        byte[]    tmp = new byte[contents.length];
        
        System.arraycopy(contents, 0, tmp, 0, tmp.length);
        
        return tmp;
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(tag, contents, true);
    }
}
