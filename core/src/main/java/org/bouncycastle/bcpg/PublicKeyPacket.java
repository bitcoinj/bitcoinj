package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

/**
 * basic packet for a PGP public key
 */
public class PublicKeyPacket 
    extends ContainedPacket implements PublicKeyAlgorithmTags
{
    private int            version;
    private long           time;
    private int            validDays;
    private int            algorithm;
    private BCPGKey        key;
    
    PublicKeyPacket(
        BCPGInputStream    in)
        throws IOException
    {      
        version = in.read();
        time = ((long)in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
 
        if (version <= 3)
        {
            validDays = (in.read() << 8) | in.read();
        }
        
        algorithm = (byte)in.read();

        switch (algorithm)
        {
        case RSA_ENCRYPT:
        case RSA_GENERAL:
        case RSA_SIGN:
            key = new RSAPublicBCPGKey(in);
            break;
        case DSA:
            key = new DSAPublicBCPGKey(in);
            break;
        case ELGAMAL_ENCRYPT:
        case ELGAMAL_GENERAL:
            key = new ElGamalPublicBCPGKey(in);
            break;
        case EC:
            key = new ECDHPublicBCPGKey(in);
            break;
        case ECDSA:
            key = new ECDSAPublicBCPGKey(in);
            break;
        default:
            throw new IOException("unknown PGP public key algorithm encountered");
        }
    }
    
    /**
     * Construct version 4 public key packet.
     * 
     * @param algorithm
     * @param time
     * @param key
     */
    public PublicKeyPacket(
        int        algorithm,
        Date       time,
        BCPGKey    key)
    {
        this.version = 4;
        this.time = time.getTime() / 1000;
        this.algorithm = algorithm;
        this.key = key;
    }
    
    public int getVersion()
    {
        return version;
    }
    
    public int getAlgorithm()
    {
        return algorithm;
    }
    
    public int getValidDays()
    {
        return validDays;
    }
    
    public Date getTime()
    {
        return new Date(time * 1000);
    }
    
    public BCPGKey getKey()
    {
        return key;
    }
    
    public byte[] getEncodedContents() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);
    
        pOut.write(version);
    
        pOut.write((byte)(time >> 24));
        pOut.write((byte)(time >> 16));
        pOut.write((byte)(time >> 8));
        pOut.write((byte)time);
    
        if (version <= 3)
        {
            pOut.write((byte)(validDays >> 8));
            pOut.write((byte)validDays);
        }
    
        pOut.write(algorithm);
    
        pOut.writeObject((BCPGObject)key);
    
        return bOut.toByteArray();
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(PUBLIC_KEY, getEncodedContents(), true);
    }
}
