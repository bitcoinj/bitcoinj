package org.bouncycastle.bcpg;

import java.io.*;
import java.math.BigInteger;

/**
 * base class for an ElGamal Public Key.
 */
public class ElGamalPublicBCPGKey 
    extends BCPGObject implements BCPGKey 
{
    MPInteger    p;
    MPInteger    g;
    MPInteger    y;
    
    /**
     * 
     */
    public ElGamalPublicBCPGKey(
        BCPGInputStream    in)
        throws IOException
    {
        this.p = new MPInteger(in);
        this.g = new MPInteger(in);
        this.y = new MPInteger(in);
    }

    public ElGamalPublicBCPGKey(
        BigInteger    p,
        BigInteger    g,
        BigInteger    y)
    {
        this.p = new MPInteger(p);
        this.g = new MPInteger(g);
        this.y = new MPInteger(y);
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
    
    public BigInteger getP()
    {
        return p.getValue();
    }
    
    public BigInteger getG()
    {
        return g.getValue();
    }
    
    public BigInteger getY()
    {
        return y.getValue();
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writeObject(p);
        out.writeObject(g);
        out.writeObject(y);
    }
}
