package com.google.bitcoin.bouncycastle.crypto.modes.gcm;

import com.google.bitcoin.bouncycastle.crypto.util.Pack;

abstract class GCMUtil
{
    static int[] asInts(byte[] bs)
    {
        int[] us = new int[4];
        us[0] = Pack.bigEndianToInt(bs, 0);
        us[1] = Pack.bigEndianToInt(bs, 4);
        us[2] = Pack.bigEndianToInt(bs, 8);
        us[3] = Pack.bigEndianToInt(bs, 12);
        return us;
    }

    // P is the value with only bit i=1 set
    static void multiplyP(int[] x)
    {
        boolean lsb = (x[3] & 1) != 0;
        shiftRight(x);
        if (lsb)
        {
            // R = new int[]{ 0xe1000000, 0, 0, 0 };
//            xor(v, R);
            x[0] ^= 0xe1000000;
        }
    }

    static void multiplyP8(int[] x)
    {
        for (int i = 8; i != 0; --i)
        {
            multiplyP(x);
        }
    }

    static void shiftRight(byte[] block)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i] & 0xff;
            block[i] = (byte) ((b >>> 1) | bit);
            if (++i == 16)
            {
                break;
            }
            bit = (b & 1) << 7;
        }
    }

    static void shiftRight(int[] block)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i];
            block[i] = (b >>> 1) | bit;
            if (++i == 4)
            {
                break;
            }
            bit = b << 31;
        }
    }

    static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }

    static void xor(int[] block, int[] val)
    {
        for (int i = 3; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }
}
