package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;

/**
 * packet giving signature creation time.
 */
public class PreferredAlgorithms 
    extends SignatureSubpacket
{    
    private static byte[] intToByteArray(
        int[]    v)
    {
        byte[]    data = new byte[v.length];
        
        for (int i = 0; i != v.length; i++)
        {
            data[i] = (byte)v[i];
        }
        
        return data;
    }
    
    public PreferredAlgorithms(
        int        type,
        boolean    critical,
        byte[]     data)
    {
        super(type, critical, data);
    }
    
    public PreferredAlgorithms(
        int        type,
        boolean    critical,
        int[]      preferrences)
    {
        super(type, critical, intToByteArray(preferrences));
    }
    
    /**
     * @deprecated mispelt!
     */
    public int[] getPreferrences()
    {
        return getPreferences();
    }

    public int[] getPreferences()
    {
        int[]    v = new int[data.length];
        
        for (int i = 0; i != v.length; i++)
        {
            v[i] = data[i] & 0xff;
        }
        
        return v;
    }
}
