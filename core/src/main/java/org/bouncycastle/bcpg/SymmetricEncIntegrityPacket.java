package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 */
public class SymmetricEncIntegrityPacket 
    extends InputStreamPacket
{    
    int        version;
    
    SymmetricEncIntegrityPacket(
        BCPGInputStream    in)
        throws IOException
    {
        super(in);
        
        version = in.read();
    }
}
