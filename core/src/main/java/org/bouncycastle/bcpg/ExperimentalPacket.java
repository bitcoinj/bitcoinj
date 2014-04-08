package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

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
        this.contents = in.readAll();
    }

    public int getTag()
    {
        return tag;
    }
    
    public byte[] getContents()
    {
        return Arrays.clone(contents);
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(tag, contents, true);
    }
}
