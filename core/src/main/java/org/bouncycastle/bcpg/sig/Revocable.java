package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving whether or not is revocable.
 */
public class Revocable 
    extends SignatureSubpacket
{    
    private static byte[] booleanToByteArray(
        boolean    value)
    {
        byte[]    data = new byte[1];
        
        if (value)
        {
            data[0] = 1;
            return data;
        }
        else
        {
            return data;
        }
    }
    
    public Revocable(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.REVOCABLE, critical, data);
    }
    
    public Revocable(
        boolean    critical,
        boolean    isRevocable)
    {
        super(SignatureSubpacketTags.REVOCABLE, critical, booleanToByteArray(isRevocable));
    }
    
    public boolean isRevocable()
    {
        return data[0] != 0;
    }
}
