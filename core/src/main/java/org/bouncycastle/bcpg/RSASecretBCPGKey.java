package org.bouncycastle.bcpg;

import java.io.*;
import java.math.BigInteger;

/**
 * base class for an RSA Secret (or Private) Key.
 */
public class RSASecretBCPGKey 
    extends BCPGObject implements BCPGKey 
{
    MPInteger    d;
    MPInteger    p;
    MPInteger    q;
    MPInteger    u;
    
    BigInteger    expP, expQ, crt;
    
    /**
     * 
     * @param in
     * @throws IOException
     */
    public RSASecretBCPGKey(
        BCPGInputStream    in)
        throws IOException
    {
        this.d = new MPInteger(in);
        this.p = new MPInteger(in);
        this.q = new MPInteger(in);
        this.u = new MPInteger(in);

        expP = d.getValue().remainder(p.getValue().subtract(BigInteger.valueOf(1)));
        expQ = d.getValue().remainder(q.getValue().subtract(BigInteger.valueOf(1)));
        crt = q.getValue().modInverse(p.getValue());
    }
    
    /**
     * 
     * @param d
     * @param p
     * @param q
     */
    public RSASecretBCPGKey(
        BigInteger    d,
        BigInteger    p,
        BigInteger    q)
    {
        //
        // pgp requires (p < q)
        //
        int cmp = p.compareTo(q);
        if (cmp >= 0)
        {
            if (cmp == 0)
            {
                throw new IllegalArgumentException("p and q cannot be equal");
            }

            BigInteger tmp = p;
            p = q;
            q = tmp;
        }

        this.d = new MPInteger(d);
        this.p = new MPInteger(p);
        this.q = new MPInteger(q);
        this.u = new MPInteger(p.modInverse(q));

        expP = d.remainder(p.subtract(BigInteger.valueOf(1)));
        expQ = d.remainder(q.subtract(BigInteger.valueOf(1)));
        crt = q.modInverse(p);
    }
    
    /**
     * return the modulus for this key.
     * 
     * @return BigInteger
     */
    public BigInteger getModulus()
    {
        return p.getValue().multiply(q.getValue());
    }
    
    /**
     * return the private exponent for this key.
     * 
     * @return BigInteger
     */
    public BigInteger getPrivateExponent()
    {
        return d.getValue();
    }
    
    /**
     * return the prime P
     */
    public BigInteger getPrimeP()
    {
        return p.getValue();
    }
    
    /**
     * return the prime Q
     */
    public BigInteger getPrimeQ()
    {
        return q.getValue();
    }
    
    /**
     * return the prime exponent of p
     */
    public BigInteger getPrimeExponentP()
    {
        return expP;
    }
    
    /**
     * return the prime exponent of q
     */
    public BigInteger getPrimeExponentQ()
    {
        return expQ;
    }
    
    /**
     * return the crt coefficient
     */
    public BigInteger getCrtCoefficient()
    {
        return crt;
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
        out.writeObject(d);
        out.writeObject(p);
        out.writeObject(q);
        out.writeObject(u);
    }
}
