package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving time after creation at which the key expires.
 */
public class KeyExpirationTime 
    extends SignatureSubpacket
{
    protected static byte[] timeToBytes(
        long    t)
    {
        byte[]    data = new byte[4];
        
        data[0] = (byte)(t >> 24);
        data[1] = (byte)(t >> 16);
        data[2] = (byte)(t >> 8);
        data[3] = (byte)t;
        
        return data;
    }
    
    public KeyExpirationTime(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.KEY_EXPIRE_TIME, critical, data);
    }
    
    public KeyExpirationTime(
        boolean    critical,
        long       seconds)
    {
        super(SignatureSubpacketTags.KEY_EXPIRE_TIME, critical, timeToBytes(seconds));
    }
    
    /**
     * Return the number of seconds after creation time a key is valid for.
     * 
     * @return second count for key validity.
     */
    public long getTime()
    {
        long    time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        
        return time;
    }
}
