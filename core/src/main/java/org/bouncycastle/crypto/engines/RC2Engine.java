package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RC2Parameters;

/**
 * an implementation of RC2 as described in RFC 2268
 *      "A Description of the RC2(r) Encryption Algorithm" R. Rivest.
 */
public class RC2Engine
    implements BlockCipher
{
    //
    // the values we use for key expansion (based on the digits of PI)
    //
    private static byte[] piTable =
    {
        (byte)0xd9, (byte)0x78, (byte)0xf9, (byte)0xc4, (byte)0x19, (byte)0xdd, (byte)0xb5, (byte)0xed, 
        (byte)0x28, (byte)0xe9, (byte)0xfd, (byte)0x79, (byte)0x4a, (byte)0xa0, (byte)0xd8, (byte)0x9d, 
        (byte)0xc6, (byte)0x7e, (byte)0x37, (byte)0x83, (byte)0x2b, (byte)0x76, (byte)0x53, (byte)0x8e, 
        (byte)0x62, (byte)0x4c, (byte)0x64, (byte)0x88, (byte)0x44, (byte)0x8b, (byte)0xfb, (byte)0xa2, 
        (byte)0x17, (byte)0x9a, (byte)0x59, (byte)0xf5, (byte)0x87, (byte)0xb3, (byte)0x4f, (byte)0x13, 
        (byte)0x61, (byte)0x45, (byte)0x6d, (byte)0x8d, (byte)0x9, (byte)0x81, (byte)0x7d, (byte)0x32, 
        (byte)0xbd, (byte)0x8f, (byte)0x40, (byte)0xeb, (byte)0x86, (byte)0xb7, (byte)0x7b, (byte)0xb, 
        (byte)0xf0, (byte)0x95, (byte)0x21, (byte)0x22, (byte)0x5c, (byte)0x6b, (byte)0x4e, (byte)0x82, 
        (byte)0x54, (byte)0xd6, (byte)0x65, (byte)0x93, (byte)0xce, (byte)0x60, (byte)0xb2, (byte)0x1c, 
        (byte)0x73, (byte)0x56, (byte)0xc0, (byte)0x14, (byte)0xa7, (byte)0x8c, (byte)0xf1, (byte)0xdc, 
        (byte)0x12, (byte)0x75, (byte)0xca, (byte)0x1f, (byte)0x3b, (byte)0xbe, (byte)0xe4, (byte)0xd1, 
        (byte)0x42, (byte)0x3d, (byte)0xd4, (byte)0x30, (byte)0xa3, (byte)0x3c, (byte)0xb6, (byte)0x26, 
        (byte)0x6f, (byte)0xbf, (byte)0xe, (byte)0xda, (byte)0x46, (byte)0x69, (byte)0x7, (byte)0x57, 
        (byte)0x27, (byte)0xf2, (byte)0x1d, (byte)0x9b, (byte)0xbc, (byte)0x94, (byte)0x43, (byte)0x3, 
        (byte)0xf8, (byte)0x11, (byte)0xc7, (byte)0xf6, (byte)0x90, (byte)0xef, (byte)0x3e, (byte)0xe7, 
        (byte)0x6, (byte)0xc3, (byte)0xd5, (byte)0x2f, (byte)0xc8, (byte)0x66, (byte)0x1e, (byte)0xd7, 
        (byte)0x8, (byte)0xe8, (byte)0xea, (byte)0xde, (byte)0x80, (byte)0x52, (byte)0xee, (byte)0xf7, 
        (byte)0x84, (byte)0xaa, (byte)0x72, (byte)0xac, (byte)0x35, (byte)0x4d, (byte)0x6a, (byte)0x2a, 
        (byte)0x96, (byte)0x1a, (byte)0xd2, (byte)0x71, (byte)0x5a, (byte)0x15, (byte)0x49, (byte)0x74, 
        (byte)0x4b, (byte)0x9f, (byte)0xd0, (byte)0x5e, (byte)0x4, (byte)0x18, (byte)0xa4, (byte)0xec, 
        (byte)0xc2, (byte)0xe0, (byte)0x41, (byte)0x6e, (byte)0xf, (byte)0x51, (byte)0xcb, (byte)0xcc, 
        (byte)0x24, (byte)0x91, (byte)0xaf, (byte)0x50, (byte)0xa1, (byte)0xf4, (byte)0x70, (byte)0x39, 
        (byte)0x99, (byte)0x7c, (byte)0x3a, (byte)0x85, (byte)0x23, (byte)0xb8, (byte)0xb4, (byte)0x7a, 
        (byte)0xfc, (byte)0x2, (byte)0x36, (byte)0x5b, (byte)0x25, (byte)0x55, (byte)0x97, (byte)0x31, 
        (byte)0x2d, (byte)0x5d, (byte)0xfa, (byte)0x98, (byte)0xe3, (byte)0x8a, (byte)0x92, (byte)0xae, 
        (byte)0x5, (byte)0xdf, (byte)0x29, (byte)0x10, (byte)0x67, (byte)0x6c, (byte)0xba, (byte)0xc9, 
        (byte)0xd3, (byte)0x0, (byte)0xe6, (byte)0xcf, (byte)0xe1, (byte)0x9e, (byte)0xa8, (byte)0x2c, 
        (byte)0x63, (byte)0x16, (byte)0x1, (byte)0x3f, (byte)0x58, (byte)0xe2, (byte)0x89, (byte)0xa9, 
        (byte)0xd, (byte)0x38, (byte)0x34, (byte)0x1b, (byte)0xab, (byte)0x33, (byte)0xff, (byte)0xb0, 
        (byte)0xbb, (byte)0x48, (byte)0xc, (byte)0x5f, (byte)0xb9, (byte)0xb1, (byte)0xcd, (byte)0x2e, 
        (byte)0xc5, (byte)0xf3, (byte)0xdb, (byte)0x47, (byte)0xe5, (byte)0xa5, (byte)0x9c, (byte)0x77, 
        (byte)0xa, (byte)0xa6, (byte)0x20, (byte)0x68, (byte)0xfe, (byte)0x7f, (byte)0xc1, (byte)0xad 
    };

    private static final int BLOCK_SIZE = 8;

    private int[]   workingKey;
    private boolean encrypting;

    private int[] generateWorkingKey(
        byte[]      key,
        int         bits)
    {
        int     x;
        int[]   xKey = new int[128];

        for (int i = 0; i != key.length; i++)
        {
            xKey[i] = key[i] & 0xff;
        }

        // Phase 1: Expand input key to 128 bytes
        int len = key.length;

        if (len < 128)
        {
            int     index = 0;

            x = xKey[len - 1];

            do
            {
                x = piTable[(x + xKey[index++]) & 255] & 0xff;
                xKey[len++] = x;
            }
            while (len < 128);
        }

        // Phase 2 - reduce effective key size to "bits"
        len = (bits + 7) >> 3;
        x = piTable[xKey[128 - len] & (255 >> (7 & -bits))] & 0xff;
        xKey[128 - len] = x;

        for (int i = 128 - len - 1; i >= 0; i--)
        {
                x = piTable[x ^ xKey[i + len]] & 0xff;
                xKey[i] = x;
        }

        // Phase 3 - copy to newKey in little-endian order 
        int[] newKey = new int[64];

        for (int i = 0; i != newKey.length; i++)
        {
            newKey[i] = (xKey[2 * i] + (xKey[2 * i + 1] << 8));
        }

        return newKey;
    }

    /**
     * initialise a RC2 cipher.
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
        this.encrypting = encrypting;

        if (params instanceof RC2Parameters)
        {
            RC2Parameters   param = (RC2Parameters)params;

            workingKey = generateWorkingKey(param.getKey(),
                                            param.getEffectiveKeyBits());
        }
        else if (params instanceof KeyParameter)
        {
            byte[]    key = ((KeyParameter)params).getKey();

            workingKey = generateWorkingKey(key, key.length * 8);
        }
        else
        {
            throw new IllegalArgumentException("invalid parameter passed to RC2 init - " + params.getClass().getName());
        }

    }

    public void reset()
    {
    }

    public String getAlgorithmName()
    {
        return "RC2";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    public final int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
    {
        if (workingKey == null)
        {
            throw new IllegalStateException("RC2 engine not initialised");
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

    /**
     * return the result rotating the 16 bit number in x left by y
     */
    private int rotateWordLeft(
        int x,
        int y)
    {
        x &= 0xffff;
        return (x << y) | (x >> (16 - y));
    }

    private void encryptBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        int x76, x54, x32, x10;

        x76 = ((in[inOff + 7] & 0xff) << 8) + (in[inOff + 6] & 0xff);
        x54 = ((in[inOff + 5] & 0xff) << 8) + (in[inOff + 4] & 0xff);
        x32 = ((in[inOff + 3] & 0xff) << 8) + (in[inOff + 2] & 0xff);
        x10 = ((in[inOff + 1] & 0xff) << 8) + (in[inOff + 0] & 0xff);

        for (int i = 0; i <= 16; i += 4)
        {
                x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i  ], 1);
                x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i+1], 2);
                x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i+2], 3);
                x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i+3], 5);
        }

        x10 += workingKey[x76 & 63];
        x32 += workingKey[x10 & 63];
        x54 += workingKey[x32 & 63];
        x76 += workingKey[x54 & 63];

        for (int i = 20; i <= 40; i += 4)
        {
                x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i  ], 1);
                x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i+1], 2);
                x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i+2], 3);
                x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i+3], 5);
        }

        x10 += workingKey[x76 & 63];
        x32 += workingKey[x10 & 63];
        x54 += workingKey[x32 & 63];
        x76 += workingKey[x54 & 63];

        for (int i = 44; i < 64; i += 4)
        {
                x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i  ], 1);
                x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i+1], 2);
                x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i+2], 3);
                x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i+3], 5);
        }

        out[outOff + 0] = (byte)x10;
        out[outOff + 1] = (byte)(x10 >> 8);
        out[outOff + 2] = (byte)x32;
        out[outOff + 3] = (byte)(x32 >> 8);
        out[outOff + 4] = (byte)x54;
        out[outOff + 5] = (byte)(x54 >> 8);
        out[outOff + 6] = (byte)x76;
        out[outOff + 7] = (byte)(x76 >> 8);
    }

    private void decryptBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        int x76, x54, x32, x10;

        x76 = ((in[inOff + 7] & 0xff) << 8) + (in[inOff + 6] & 0xff);
        x54 = ((in[inOff + 5] & 0xff) << 8) + (in[inOff + 4] & 0xff);
        x32 = ((in[inOff + 3] & 0xff) << 8) + (in[inOff + 2] & 0xff);
        x10 = ((in[inOff + 1] & 0xff) << 8) + (in[inOff + 0] & 0xff);

        for (int i = 60; i >= 44; i -= 4)
        {
            x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i+3]);
            x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i+2]);
            x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i+1]);
            x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i  ]);
        }

        x76 -= workingKey[x54 & 63];
        x54 -= workingKey[x32 & 63];
        x32 -= workingKey[x10 & 63];
        x10 -= workingKey[x76 & 63];

        for (int i = 40; i >= 20; i -= 4)
        {
            x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i+3]);
            x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i+2]);
            x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i+1]);
            x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i  ]);
        }

        x76 -= workingKey[x54 & 63];
        x54 -= workingKey[x32 & 63];
        x32 -= workingKey[x10 & 63];
        x10 -= workingKey[x76 & 63];

        for (int i = 16; i >= 0; i -= 4)
        {
            x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i+3]);
            x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i+2]);
            x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i+1]);
            x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i  ]);
        }

        out[outOff + 0] = (byte)x10;
        out[outOff + 1] = (byte)(x10 >> 8);
        out[outOff + 2] = (byte)x32;
        out[outOff + 3] = (byte)(x32 >> 8);
        out[outOff + 4] = (byte)x54;
        out[outOff + 5] = (byte)(x54 >> 8);
        out[outOff + 6] = (byte)x76;
        out[outOff + 7] = (byte)(x76 >> 8);
    }
}
