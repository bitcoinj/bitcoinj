package org.bouncycastle.bcpg;

/**
 * Basic type for a symmetric key encrypted packet
 */
public class SymmetricEncDataPacket 
    extends InputStreamPacket
{
    public SymmetricEncDataPacket(
        BCPGInputStream  in)
    {
        super(in);
    }
}
