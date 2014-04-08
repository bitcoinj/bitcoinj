package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving signature expiration time.
 */
public class SignatureExpirationTime 
    extends SignatureSubpacket
{
    protected static byte[] timeToBytes(
        long      t)
    {
        byte[]    data = new byte[4];
        
        data[0] = (byte)(t >> 24);
        data[1] = (byte)(t >> 16);
        data[2] = (byte)(t >> 8);
        data[3] = (byte)t;
        
        return data;
    }
    
    public SignatureExpirationTime(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.EXPIRE_TIME, critical, data);
    }
    
    public SignatureExpirationTime(
        boolean    critical,
        long       seconds)
    {
        super(SignatureSubpacketTags.EXPIRE_TIME, critical, timeToBytes(seconds));
    }
    
    /**
     * return time in seconds before signature expires after creation time.
     */
    public long getTime()
    {
        long    time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        
        return time;
    }
}
