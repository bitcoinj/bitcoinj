package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * basic packet for a PGP public key
 */
public class PublicKeyEncSessionPacket 
    extends ContainedPacket implements PublicKeyAlgorithmTags
{
    private int            version;
    private long           keyID;
    private int            algorithm;
    private byte[][]       data;

    PublicKeyEncSessionPacket(
        BCPGInputStream    in)
        throws IOException
    {      
        version = in.read();
        
        keyID |= (long)in.read() << 56;
        keyID |= (long)in.read() << 48;
        keyID |= (long)in.read() << 40;
        keyID |= (long)in.read() << 32;
        keyID |= (long)in.read() << 24;
        keyID |= (long)in.read() << 16;
        keyID |= (long)in.read() << 8;
        keyID |= in.read();
        
        algorithm = in.read();
        
        switch (algorithm)
        {
        case RSA_ENCRYPT:
        case RSA_GENERAL:
            data = new byte[1][];
            
            data[0] = new MPInteger(in).getEncoded();
            break;
        case ELGAMAL_ENCRYPT:
        case ELGAMAL_GENERAL:
            data = new byte[2][];
            
            data[0] = new MPInteger(in).getEncoded();
            data[1] = new MPInteger(in).getEncoded();
            break;
        case ECDH:
            data = new byte[1][];

            data[0] = Streams.readAll(in);
            break;
        default:
            throw new IOException("unknown PGP public key algorithm encountered");
        }
    }
    
    public PublicKeyEncSessionPacket(
        long           keyID,
        int            algorithm,
        byte[][]       data)
    {
        this.version = 3;
        this.keyID = keyID;
        this.algorithm = algorithm;
        this.data = new byte[data.length][];

        for (int i = 0; i != data.length; i++)
        {
            this.data[i] = Arrays.clone(data[i]);
        }
    }
    
    public int getVersion()
    {
        return version;
    }
    
    public long getKeyID()
    {
        return keyID;
    }
    
    public int getAlgorithm()
    {
        return algorithm;
    }
    
    public byte[][] getEncSessionKey()
    {
        return data;
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
        BCPGOutputStream       pOut = new BCPGOutputStream(bOut);
  
          pOut.write(version);
          
        pOut.write((byte)(keyID >> 56));
        pOut.write((byte)(keyID >> 48));
        pOut.write((byte)(keyID >> 40));
        pOut.write((byte)(keyID >> 32));
        pOut.write((byte)(keyID >> 24));
        pOut.write((byte)(keyID >> 16));
        pOut.write((byte)(keyID >> 8));
        pOut.write((byte)(keyID));
        
        pOut.write(algorithm);
        
        for (int i = 0; i != data.length; i++)
        {
            pOut.write(data[i]);
        }
        
        out.writePacket(PUBLIC_KEY_ENC_SESSION , bOut.toByteArray(), true);
    }
}
