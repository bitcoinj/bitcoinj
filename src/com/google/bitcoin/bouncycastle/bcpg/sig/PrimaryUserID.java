package com.google.bitcoin.bouncycastle.bcpg.sig;

import com.google.bitcoin.bouncycastle.bcpg.SignatureSubpacket;
import com.google.bitcoin.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving whether or not the signature is signed using the primary user ID for the key.
 */
public class PrimaryUserID 
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
    
    public PrimaryUserID(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.PRIMARY_USER_ID, critical, data);
    }
    
    public PrimaryUserID(
        boolean    critical,
        boolean    isPrimaryUserID)
    {
        super(SignatureSubpacketTags.PRIMARY_USER_ID, critical, booleanToByteArray(isPrimaryUserID));
    }
    
    public boolean isPrimaryUserID()
    {
        return data[0] != 0;
    }
}
