package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Basic type for a symmetric encrypted session key packet
 */
public class SymmetricKeyEncSessionPacket 
    extends ContainedPacket
{
    private int       version;
    private int       encAlgorithm;
    private S2K       s2k;
    private byte[]    secKeyData;
    
    public SymmetricKeyEncSessionPacket(
        BCPGInputStream  in)
        throws IOException
    {
        version = in.read();
        encAlgorithm = in.read();

        s2k = new S2K(in);

        this.secKeyData = in.readAll();
    }

    public SymmetricKeyEncSessionPacket(
        int       encAlgorithm,
        S2K       s2k,
        byte[]    secKeyData)
    {
        this.version = 4;
        this.encAlgorithm = encAlgorithm;
        this.s2k = s2k;
        this.secKeyData = secKeyData;
    }
    
    /**
     * @return int
     */
    public int getEncAlgorithm()
    {
        return encAlgorithm;
    }

    /**
     * @return S2K
     */
    public S2K getS2K()
    {
        return s2k;
    }

    /**
     * @return byte[]
     */
    public byte[] getSecKeyData()
    {
        return secKeyData;
    }

    /**
     * @return int
     */
    public int getVersion()
    {
        return version;
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        BCPGOutputStream        pOut = new BCPGOutputStream(bOut);

        pOut.write(version);
        pOut.write(encAlgorithm);
        pOut.writeObject(s2k);
        
        if (secKeyData != null && secKeyData.length > 0)
        {
            pOut.write(secKeyData);
        }
        
        out.writePacket(SYMMETRIC_KEY_ENC_SESSION, bOut.toByteArray(), true);
    }
}
