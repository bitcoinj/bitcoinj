package org.bouncycastle.bcpg;

import java.io.*;

/**
 * generic signature object
 */
public class OnePassSignaturePacket 
    extends ContainedPacket
{
    private int  version;
    private int  sigType;
    private int  hashAlgorithm;
    private int  keyAlgorithm;
    private long keyID;
    private int  nested;
    
    OnePassSignaturePacket(
        BCPGInputStream    in)
        throws IOException
    {
        version = in.read();
        sigType = in.read();
        hashAlgorithm = in.read();
        keyAlgorithm = in.read();
        
        keyID |= (long)in.read() << 56;
        keyID |= (long)in.read() << 48;
        keyID |= (long)in.read() << 40;
        keyID |= (long)in.read() << 32;
        keyID |= (long)in.read() << 24;
        keyID |= (long)in.read() << 16;
        keyID |= (long)in.read() << 8;
        keyID |= in.read();
        
        nested = in.read();
    }
    
    public OnePassSignaturePacket(
        int        sigType,
        int        hashAlgorithm,
        int        keyAlgorithm,
        long       keyID,
        boolean    isNested)
    {
        this.version = 3;
        this.sigType = sigType;
        this.hashAlgorithm = hashAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keyID = keyID;
        this.nested = (isNested) ? 0 : 1;
    }
    
    /**
     * Return the signature type.
     * @return the signature type
     */
    public int getSignatureType()
    {
        return sigType;
    }
    
    /**
     * return the encryption algorithm tag
     */
    public int getKeyAlgorithm()
    {
        return keyAlgorithm;
    }
    
    /**
     * return the hashAlgorithm tag
     */
    public int getHashAlgorithm()
    {
        return hashAlgorithm;
    }
    
    /**
     * @return long
     */
    public long getKeyID()
    {
        return keyID;
    }
    
    /**
     * 
     */
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream            pOut = new BCPGOutputStream(bOut);
  
        pOut.write(version);
        pOut.write(sigType);
        pOut.write(hashAlgorithm);
        pOut.write(keyAlgorithm);

        pOut.write((byte)(keyID >> 56));
        pOut.write((byte)(keyID >> 48));
        pOut.write((byte)(keyID >> 40));
        pOut.write((byte)(keyID >> 32));
        pOut.write((byte)(keyID >> 24));
        pOut.write((byte)(keyID >> 16));
        pOut.write((byte)(keyID >> 8));
        pOut.write((byte)(keyID));
        
        pOut.write(nested);
        
        out.writePacket(ONE_PASS_SIGNATURE, bOut.toByteArray(), true);
    }
}
