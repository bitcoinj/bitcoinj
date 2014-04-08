package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Packet holding the key flag values.
 */
public class KeyFlags 
    extends SignatureSubpacket
{
    public static final int CERTIFY_OTHER = 0x01;
    public static final int SIGN_DATA = 0x02;
    public static final int ENCRYPT_COMMS = 0x04;
    public static final int ENCRYPT_STORAGE = 0x08;
    public static final int SPLIT = 0x10;
    public static final int AUTHENTICATION = 0x20;
    public static final int SHARED = 0x80;
    
    private static byte[] intToByteArray(
        int    v)
    {
        byte[] tmp = new byte[4];
        int    size = 0;

        for (int i = 0; i != 4; i++)
        {
            tmp[i] = (byte)(v >> (i * 8));
            if (tmp[i] != 0)
            {
                size = i;
            }
        }

        byte[]    data = new byte[size + 1];
        
        System.arraycopy(tmp, 0, data, 0, data.length);

        return data;
    }
    
    public KeyFlags(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.KEY_FLAGS, critical, data);
    }
    
    public KeyFlags(
        boolean    critical,
        int        flags)
    {
        super(SignatureSubpacketTags.KEY_FLAGS, critical, intToByteArray(flags));
    }

    /**
     * Return the flag values contained in the first 4 octets (note: at the moment
     * the standard only uses the first one).
     *
     * @return flag values.
     */
    public int getFlags()
    {
        int flags = 0;

        for (int i = 0; i != data.length; i++)
        {
            flags |= (data[i] & 0xff) << (i * 8);
        }

        return flags;
    }
}
