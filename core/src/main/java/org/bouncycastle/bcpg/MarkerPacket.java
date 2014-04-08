package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Basic type for a marker packet
 */
public class MarkerPacket 
    extends ContainedPacket
{    
    // "PGP"
        
    byte[]    marker = { (byte)0x50, (byte)0x47, (byte)0x50 };
    
    public MarkerPacket(
        BCPGInputStream  in)
        throws IOException
    {
         in.readFully(marker);
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(MARKER, marker, true);
    }
}
