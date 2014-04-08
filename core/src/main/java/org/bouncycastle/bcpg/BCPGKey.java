package org.bouncycastle.bcpg;

/**
 * base interface for a PGP key
 */
public interface BCPGKey
{
    /**
     * Return the base format for this key - in the case of the symmetric keys it will generally
     * be raw indicating that the key is just a straight byte representation, for an asymmetric
     * key the format will be PGP, indicating the key is a string of MPIs encoded in PGP format.
     * 
     * @return "RAW" or "PGP"
     */
    public String getFormat();
    
    /**
     * return a string of bytes giving the encoded format of the key, as described by it's format.
     * 
     * @return byte[]
     */
    public byte[] getEncoded();
    
}
