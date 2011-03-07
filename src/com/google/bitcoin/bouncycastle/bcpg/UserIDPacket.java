package com.google.bitcoin.bouncycastle.bcpg;

import java.io.IOException;

import com.google.bitcoin.bouncycastle.util.Strings;

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
        idData = new byte[in.available()];
        in.readFully(idData);
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
