package org.bouncycastle.bcpg;

public class CRC24
{
    private static final int CRC24_INIT = 0x0b704ce;
    private static final int CRC24_POLY = 0x1864cfb;
                                                                                
    private int crc = CRC24_INIT;
                                                                                
    public CRC24()
    {
    }

    public void update(
        int b)
    {
        crc ^= b << 16;
        for (int i = 0; i < 8; i++)
        {
            crc <<= 1;
            if ((crc & 0x1000000) != 0)
            {
                crc ^= CRC24_POLY;
            }
        }
    }

    public int getValue()
    {
        return crc;
    }

    public void reset()
    {
        crc = CRC24_INIT;
    }
}
