package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving the User ID of the signer.
 */
public class SignerUserID 
    extends SignatureSubpacket
{    
    private static byte[] userIDToBytes(
        String    id)
    {
        byte[] idData = new byte[id.length()];
        
        for (int i = 0; i != id.length(); i++)
        {
            idData[i] = (byte)id.charAt(i);
        }
        
        return idData;
    }
    
    public SignerUserID(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, data);
    }
    
    public SignerUserID(
        boolean    critical,
        String     userID)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, userIDToBytes(userID));
    }
    
    public String getID()
    {
        char[]    chars = new char[data.length];
        
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(data[i] & 0xff);
        }
        
        return new String(chars);
    }
}
