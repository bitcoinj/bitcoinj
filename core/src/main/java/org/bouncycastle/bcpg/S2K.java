package org.bouncycastle.bcpg;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * The string to key specifier class
 */
public class S2K 
    extends BCPGObject
{
    private static final int EXPBIAS = 6;
    
    public static final int SIMPLE = 0;
    public static final int SALTED = 1;
    public static final int SALTED_AND_ITERATED = 3;
    public static final int GNU_DUMMY_S2K = 101;
    
    int       type;
    int       algorithm;
    byte[]    iv;
    int       itCount = -1;
    int       protectionMode = -1;
    
    S2K(
        InputStream    in)
        throws IOException
    {
        DataInputStream    dIn = new DataInputStream(in);
        
        type = dIn.read();
        algorithm = dIn.read();
        
        //
        // if this happens we have a dummy-S2K packet.
        //
        if (type != GNU_DUMMY_S2K)
        {
            if (type != 0)
            {
                iv = new byte[8];
                dIn.readFully(iv, 0, iv.length);

                if (type == 3)
                {
                    itCount = dIn.read();
                }
            }
        }
        else
        {
            dIn.read(); // G
            dIn.read(); // N
            dIn.read(); // U
            protectionMode = dIn.read(); // protection mode
        }
    }
    
    public S2K(
        int        algorithm)
    {
        this.type = 0;
        this.algorithm = algorithm;
    }
    
    public S2K(
        int        algorithm,
        byte[]    iv)
    {
        this.type = 1;
        this.algorithm = algorithm;
        this.iv = iv;
    }

    public S2K(
        int       algorithm,
        byte[]    iv,
        int       itCount)
    {
        this.type = 3;
        this.algorithm = algorithm;
        this.iv = iv;
        this.itCount = itCount;
    }
    
    public int getType()
    {
        return type;
    }
    
    /**
     * return the hash algorithm for this S2K
     */
    public int getHashAlgorithm()
    {
        return algorithm;
    }
    
    /**
     * return the iv for the key generation algorithm
     */
    public byte[] getIV()
    {
        return iv;
    }
    
    /**
     * return the iteration count
     */
    public long getIterationCount()
    {
        return (16 + (itCount & 15)) << ((itCount >> 4) + EXPBIAS);
    }
    
    /**
     * the protection mode - only if GNU_DUMMY_S2K
     */
    public int getProtectionMode()
    {
        return protectionMode;
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.write(type);
        out.write(algorithm);
    
        if (type != GNU_DUMMY_S2K)
        {
            if (type != 0)
            {
                out.write(iv);
            }
            
            if (type == 3)
            {
                out.write(itCount);
            }
        }
        else
        {
            out.write('G');
            out.write('N');
            out.write('U');
            out.write(protectionMode);
        }
    }
}
