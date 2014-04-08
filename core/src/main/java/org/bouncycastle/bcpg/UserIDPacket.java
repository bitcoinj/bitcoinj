package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Strings;

/**
 * Basic type for a user ID packet.
 */
public class UserIDPacket 
    extends ContainedPacket
{    
    private byte[]    idData;
    
    public UserIDPacket(
        BCPGInputStream  in)
        throws IOException
    {
        this.idData = in.readAll();
    }

    public UserIDPacket(
        String    id)
    {
        this.idData = Strings.toUTF8ByteArray(id);
    }
    
    public String getID()
    {
        return Strings.fromUTF8ByteArray(idData);
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(USER_ID, idData, true);
    }
}
