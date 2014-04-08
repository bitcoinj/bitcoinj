package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * basic packet for a PGP secret key
 */
public class SecretKeyPacket 
    extends ContainedPacket implements PublicKeyAlgorithmTags
{
    public static final int USAGE_NONE = 0x00;
    public static final int USAGE_CHECKSUM = 0xff;
    public static final int USAGE_SHA1 = 0xfe;

    private PublicKeyPacket    pubKeyPacket;
    private byte[]             secKeyData;
    private int                s2kUsage;
    private int                encAlgorithm;
    private S2K                s2k;
    private byte[]             iv;
    
    /**
     * 
     * @param in
     * @throws IOException
     */
    SecretKeyPacket(
        BCPGInputStream    in)
        throws IOException
    {
        if (this instanceof SecretSubkeyPacket)
        {
            pubKeyPacket = new PublicSubkeyPacket(in);
        }
        else
        {
            pubKeyPacket = new PublicKeyPacket(in);
        }

        s2kUsage = in.read();

        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1)
        {
            encAlgorithm = in.read();
            s2k = new S2K(in);
        }
        else
        {
            encAlgorithm = s2kUsage;
        }

        if (!(s2k != null && s2k.getType() == S2K.GNU_DUMMY_S2K && s2k.getProtectionMode() == 0x01))
        {
            if (s2kUsage != 0) 
            {
                if (encAlgorithm < 7)
                {
                    iv = new byte[8];
                }
                else
                {
                    iv = new byte[16];
                }
                in.readFully(iv, 0, iv.length);
            }
        }

        this.secKeyData = in.readAll();
    }

    /**
     * 
     * @param pubKeyPacket
     * @param encAlgorithm
     * @param s2k
     * @param iv
     * @param secKeyData
     */
    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int             encAlgorithm,
        S2K             s2k,
        byte[]          iv,
        byte[]          secKeyData)
    {
        this.pubKeyPacket = pubKeyPacket;
        this.encAlgorithm = encAlgorithm;
        
        if (encAlgorithm != SymmetricKeyAlgorithmTags.NULL)
        {
            this.s2kUsage = USAGE_CHECKSUM;
        }
        else
        {
            this.s2kUsage = USAGE_NONE;
        }
        
        this.s2k = s2k;
        this.iv = iv;
        this.secKeyData = secKeyData;
    }
    
    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int             encAlgorithm,
        int             s2kUsage,
        S2K             s2k,
        byte[]          iv,
        byte[]          secKeyData)
    {
        this.pubKeyPacket = pubKeyPacket;
        this.encAlgorithm = encAlgorithm;
        this.s2kUsage = s2kUsage;
        this.s2k = s2k;
        this.iv = iv;
        this.secKeyData = secKeyData;
    }

    public int getEncAlgorithm()
    {
        return encAlgorithm;
    }
    
    public int getS2KUsage()
    {
        return s2kUsage;
    }

    public byte[] getIV()
    {
        return iv;
    }
    
    public S2K getS2K()
    {
        return s2k;
    }
    
    public PublicKeyPacket getPublicKeyPacket()
    {
        return pubKeyPacket;
    }
    
    public byte[] getSecretKeyData()
    {
        return secKeyData;
    }
    
    public byte[] getEncodedContents()
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);
        
        pOut.write(pubKeyPacket.getEncodedContents());
        
        pOut.write(s2kUsage);

        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1)
        {
            pOut.write(encAlgorithm);
            pOut.writeObject(s2k);
        }
        
        if (iv != null)
        {
            pOut.write(iv);
        }
        
        if (secKeyData != null && secKeyData.length > 0)
        {
            pOut.write(secKeyData);
        }

        return bOut.toByteArray();
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(SECRET_KEY, getEncodedContents(), true);
    }
}
