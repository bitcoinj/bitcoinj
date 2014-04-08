package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * a class that provides a basic SKIPJACK engine.
 */
public class SkipjackEngine
    implements BlockCipher
{
    static final int BLOCK_SIZE = 8;

    static short ftable[] =
    { 
        0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9, 
        0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28, 
        0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53, 
        0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2, 
        0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8, 
        0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90, 
        0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76, 
        0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d, 
        0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18, 
        0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4, 
        0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40, 
        0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5, 
        0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2, 
        0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8, 
        0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac, 
        0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
    };

    private int[]       key0, key1, key2, key3;
    private boolean     encrypting;

    /**
     * initialise a SKIPJACK cipher.
     *
     * @param encrypting whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           encrypting,
        CipherParameters  params)
    {
        if (!(params instanceof KeyParameter))
        {
        throw new IllegalArgumentException("invalid parameter passed to SKIPJACK init - " + params.getClass().getName());
        }

        byte[] keyBytes = ((KeyParameter)params).getKey();

        this.encrypting = encrypting;
        this.key0 = new int[32];
        this.key1 = new int[32];
        this.key2 = new int[32];
        this.key3 = new int[32];

        //
        // expand the key to 128 bytes in 4 parts (saving us a modulo, multiply
        // and an addition).
        //
        for (int i = 0; i < 32; i ++)
        {
            key0[i] = keyBytes[(i * 4) % 10] & 0xff;
            key1[i] = keyBytes[(i * 4 + 1) % 10] & 0xff;
            key2[i] = keyBytes[(i * 4 + 2) % 10] & 0xff;
            key3[i] = keyBytes[(i * 4 + 3) % 10] & 0xff;
        }
    }

    public String getAlgorithmName()
    {
        return "SKIPJACK";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
    {
        if (key1 == null)
        {
            throw new IllegalStateException("SKIPJACK engine not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        if (encrypting)
        {
            encryptBlock(in, inOff, out, outOff);
        }
        else
        {
            decryptBlock(in, inOff, out, outOff);
        }

        return BLOCK_SIZE;
    }

    public void reset()
    {
    }

    /**
     * The G permutation
     */
    private int g(
        int     k,
        int     w)
    {
        int g1, g2, g3, g4, g5, g6;

        g1 = (w >> 8) & 0xff;
        g2 = w & 0xff;

        g3 = ftable[g2 ^ key0[k]] ^ g1;
        g4 = ftable[g3 ^ key1[k]] ^ g2;
        g5 = ftable[g4 ^ key2[k]] ^ g3;
        g6 = ftable[g5 ^ key3[k]] ^ g4;

        return ((g5 << 8) + g6);
    }

    public int encryptBlock(
        byte[]      in,
        int         inOff,
        byte[]      out,
        int         outOff)
    {
        int w1 = (in[inOff + 0] << 8) + (in[inOff + 1] & 0xff);
        int w2 = (in[inOff + 2] << 8) + (in[inOff + 3] & 0xff);
        int w3 = (in[inOff + 4] << 8) + (in[inOff + 5] & 0xff);
        int w4 = (in[inOff + 6] << 8) + (in[inOff + 7] & 0xff);

        int k = 0;

        for (int t = 0; t < 2; t++)
        {
            for(int i = 0; i < 8; i++)
            {
                int tmp = w4;
                w4 = w3;
                w3 = w2;
                w2 = g(k, w1);
                w1 = w2 ^ tmp ^ (k + 1);
                k++;
            }

            for(int i = 0; i < 8; i++)
            {
                int tmp = w4;
                w4 = w3;
                w3 = w1 ^ w2 ^ (k + 1);
                w2 = g(k, w1);
                w1 = tmp;
                k++;
            }
        }

        out[outOff + 0] = (byte)((w1 >> 8));
        out[outOff + 1] = (byte)(w1);
        out[outOff + 2] = (byte)((w2 >> 8));
        out[outOff + 3] = (byte)(w2);
        out[outOff + 4] = (byte)((w3 >> 8));
        out[outOff + 5] = (byte)(w3);
        out[outOff + 6] = (byte)((w4 >> 8));
        out[outOff + 7] = (byte)(w4);

        return BLOCK_SIZE;
    }

    /**
     * the inverse of the G permutation.
     */
    private int h(
        int     k,
        int     w)
    {
        int h1, h2, h3, h4, h5, h6;

        h1 = w & 0xff;
        h2 = (w >> 8) & 0xff;

        h3 = ftable[h2 ^ key3[k]] ^ h1;
        h4 = ftable[h3 ^ key2[k]] ^ h2;
        h5 = ftable[h4 ^ key1[k]] ^ h3;
        h6 = ftable[h5 ^ key0[k]] ^ h4;

        return ((h6 << 8) + h5);
    }

    public int decryptBlock(
        byte[]      in,
        int         inOff,
        byte[]      out,
        int         outOff)
    {
        int w2 = (in[inOff + 0] << 8) + (in[inOff + 1] & 0xff);
        int w1 = (in[inOff + 2] << 8) + (in[inOff + 3] & 0xff);
        int w4 = (in[inOff + 4] << 8) + (in[inOff + 5] & 0xff);
        int w3 = (in[inOff + 6] << 8) + (in[inOff + 7] & 0xff);

        int k = 31;

        for (int t = 0; t < 2; t++)
        {
            for(int i = 0; i < 8; i++)
            {
                int tmp = w4;
                w4 = w3;
                w3 = w2;
                w2 = h(k, w1);
                w1 = w2 ^ tmp ^ (k + 1);
                k--;
            }

            for(int i = 0; i < 8; i++)
            {
                int tmp = w4;
                w4 = w3;
                w3 = w1 ^ w2 ^ (k + 1);
                w2 = h(k, w1);
                w1 = tmp;
                k--;
            }
        }

        out[outOff + 0] = (byte)((w2 >> 8));
        out[outOff + 1] = (byte)(w2);
        out[outOff + 2] = (byte)((w1 >> 8));
        out[outOff + 3] = (byte)(w1);
        out[outOff + 4] = (byte)((w4 >> 8));
        out[outOff + 5] = (byte)(w4);
        out[outOff + 6] = (byte)((w3 >> 8));
        out[outOff + 7] = (byte)(w3);

        return BLOCK_SIZE;
    }
}
