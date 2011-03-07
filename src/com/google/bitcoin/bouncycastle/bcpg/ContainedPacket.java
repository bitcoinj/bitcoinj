package com.google.bitcoin.bouncycastle.bcpg;

import java.io.*;

/**
 * Basic type for a PGP packet.
 */
public abstract class ContainedPacket 
    extends Packet
{
    public byte[] getEncoded() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);
        
        pOut.writePacket(this);
        
        return bOut.toByteArray();
    }
    
    public abstract void encode(
        BCPGOutputStream    pOut)
        throws IOException;
}
