package org.bouncycastle.bcpg;

import java.io.*;
import java.math.BigInteger;

/**
 * base class for an ElGamal Secret Key.
 */
public class ElGamalSecretBCPGKey 
    extends BCPGObject implements BCPGKey 
{
    MPInteger    x;
    
    /**
     * 
     * @param in
     * @throws IOException
     */
    public ElGamalSecretBCPGKey(
        BCPGInputStream    in)
        throws IOException
    {
        this.x = new MPInteger(in);
    }
    
    /**
     * 
     * @param x
     */
    public ElGamalSecretBCPGKey(
        BigInteger    x)
    {
        this.x = new MPInteger(x);
    }
    
    /**
     *  return "PGP"
     * 
     * @see org.bouncycastle.bcpg.BCPGKey#getFormat()
     */
    public String getFormat() 
    {
        return "PGP";
    }

    public BigInteger getX()
    {
        return x.getValue();
    }
    
    /**
     * return the standard PGP encoding of the key.
     * 
     * @see org.bouncycastle.bcpg.BCPGKey#getEncoded()
     */
    public byte[] getEncoded() 
    {
        try
        { 
            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
            BCPGOutputStream         pgpOut = new BCPGOutputStream(bOut);
        
            pgpOut.writeObject(this);
        
            return bOut.toByteArray();
        }
        catch (IOException e)
        {
            return null;
        }
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writeObject(x);
    }
}
