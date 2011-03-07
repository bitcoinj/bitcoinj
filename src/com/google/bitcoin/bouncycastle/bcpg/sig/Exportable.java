package com.google.bitcoin.bouncycastle.bcpg.sig;

import com.google.bitcoin.bouncycastle.bcpg.SignatureSubpacket;
import com.google.bitcoin.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving signature creation time.
 */
public class Exportable 
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
    
    public Exportable(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.EXPORTABLE, critical, data);
    }
    
    public Exportable(
        boolean    critical,
        boolean    isExportable)
    {
        super(SignatureSubpacketTags.EXPORTABLE, critical, booleanToByteArray(isExportable));
    }
    
    public boolean isExportable()
    {
        return data[0] != 0;
    }
}
