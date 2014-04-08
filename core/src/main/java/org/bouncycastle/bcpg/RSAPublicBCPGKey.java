package org.bouncycastle.bcpg;

import java.math.BigInteger;
import java.io.*;

/**
 * base class for an RSA Public Key.
 */
public class RSAPublicBCPGKey 
    extends BCPGObject implements BCPGKey 
{
    MPInteger    n;
    MPInteger    e;
    
    /**
     * Construct an RSA public key from the passed in stream.
     * 
     * @param in
     * @throws IOException
     */
    public RSAPublicBCPGKey(
        BCPGInputStream    in)
        throws IOException
    {
        this.n = new MPInteger(in);
        this.e = new MPInteger(in);
    }

    /**
     * 
     * @param n the modulus
     * @param e the public exponent
     */
    public RSAPublicBCPGKey(
        BigInteger    n,
        BigInteger    e)
    {
        this.n = new MPInteger(n);
        this.e = new MPInteger(e);
    }
    
    public BigInteger getPublicExponent()
    {
        return e.getValue();
    }
    
    public BigInteger getModulus()
    {
        return n.getValue();
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
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writeObject(n);
        out.writeObject(e);
    }
}
