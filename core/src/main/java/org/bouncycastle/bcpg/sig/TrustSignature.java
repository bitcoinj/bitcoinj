package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving trust.
 */
public class TrustSignature 
    extends SignatureSubpacket
{    
    private static byte[] intToByteArray(
        int    v1,
        int    v2)
    {
        byte[]    data = new byte[2];
        
        data[0] = (byte)v1;
        data[1] = (byte)v2;
        
        return data;
    }
    
    public TrustSignature(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.TRUST_SIG, critical, data);
    }
    
    public TrustSignature(
        boolean    critical,
        int        depth,
        int        trustAmount)
    {
        super(SignatureSubpacketTags.TRUST_SIG, critical, intToByteArray(depth, trustAmount));
    }
    
    public int getDepth()
    {
        return data[0] & 0xff;
    }
    
    public int getTrustAmount()
    {
        return data[1] & 0xff;
    }
}
