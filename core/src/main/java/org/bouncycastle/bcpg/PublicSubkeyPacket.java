package org.bouncycastle.bcpg;

import java.io.*;
import java.util.Date;

/**
 * basic packet for a PGP public key
 */
public class PublicSubkeyPacket 
    extends PublicKeyPacket
{
    PublicSubkeyPacket(
        BCPGInputStream    in)
        throws IOException
    {      
        super(in);
    }
    
    /**
     * Construct version 4 public key packet.
     * 
     * @param algorithm
     * @param time
     * @param key
     */
    public PublicSubkeyPacket(
        int       algorithm,
        Date      time,
        BCPGKey   key)
    {
        super(algorithm, time, key);
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(PUBLIC_SUBKEY, getEncodedContents(), true);
    }
}
