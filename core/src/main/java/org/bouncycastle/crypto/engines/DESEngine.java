package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * a class that provides a basic DES engine.
 */
public class DESEngine
    implements BlockCipher
{
    protected static final int  BLOCK_SIZE = 8;

    private int[]               workingKey = null;

    /**
     * standard constructor.
     */
    public DESEngine()
    {
    }

    /**
     * initialise a DES cipher.
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
        if (params instanceof KeyParameter)
        {
            if (((KeyParameter)params).getKey().length > 8)
            {
                throw new IllegalArgumentException("DES key too long - should be 8 bytes");
            }
            
            workingKey = generateWorkingKey(encrypting,
                                  ((KeyParameter)params).getKey());

            return;
        }

        throw new IllegalArgumentException("invalid parameter passed to DES init - " + params.getClass().getName());
    }

    public String getAlgorithmName()
    {
        return "DES";
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
        if (workingKey == null)
        {
            throw new IllegalStateException("DES engine not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        desFunc(workingKey, in, inOff, out, outOff);

        return BLOCK_SIZE;
    }

    public void reset()
    {
    }

    /**
     * what follows is mainly taken from "Applied Cryptography", by
     * Bruce Schneier, however it also bears great resemblance to Richard
     * Outerbridge's D3DES...
     */

//    private static final short[]    Df_Key =
//        {
//            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
//            0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
//            0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
//        };

    private static final short[]    bytebit =
        {
            0200, 0100, 040, 020, 010, 04, 02, 01
        };

    private static final int[]    bigbyte =
        {
            0x800000, 0x400000, 0x200000, 0x100000,
            0x80000,  0x40000,  0x20000,  0x10000,
            0x8000,      0x4000,   0x2000,   0x1000,
            0x800,    0x400,    0x200,    0x100,
            0x80,      0x40,        0x20,     0x10,
            0x8,      0x4,      0x2,      0x1
        };

    /*
     * Use the key schedule specified in the Standard (ANSI X3.92-1981).
     */

    private static final byte[]    pc1 =
        {
            56, 48, 40, 32, 24, 16,  8,   0, 57, 49, 41, 33, 25, 17,
             9,  1, 58, 50, 42, 34, 26,  18, 10,  2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14,   6, 61, 53, 45, 37, 29, 21,
            13,  5, 60, 52, 44, 36, 28,  20, 12,  4, 27, 19, 11,  3
        };

    private static final byte[] totrot =
        {
            1, 2, 4, 6, 8, 10, 12, 14,
            15, 17, 19, 21, 23, 25, 27, 28
        };

    private static final byte[] pc2 =
        {
            13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
            22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
            40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
        };

    private static final int[] SP1 = {
        0x01010400, 0x00000000, 0x00010000, 0x01010404,
        0x01010004, 0x00010404, 0x00000004, 0x00010000,
        0x00000400, 0x01010400, 0x01010404, 0x00000400,
        0x01000404, 0x01010004, 0x01000000, 0x00000004,
        0x00000404, 0x01000400, 0x01000400, 0x00010400,
        0x00010400, 0x01010000, 0x01010000, 0x01000404,
        0x00010004, 0x01000004, 0x01000004, 0x00010004,
        0x00000000, 0x00000404, 0x00010404, 0x01000000,
        0x00010000, 0x01010404, 0x00000004, 0x01010000,
        0x01010400, 0x01000000, 0x01000000, 0x00000400,
        0x01010004, 0x00010000, 0x00010400, 0x01000004,
        0x00000400, 0x00000004, 0x01000404, 0x00010404,
        0x01010404, 0x00010004, 0x01010000, 0x01000404,
        0x01000004, 0x00000404, 0x00010404, 0x01010400,
        0x00000404, 0x01000400, 0x01000400, 0x00000000,
        0x00010004, 0x00010400, 0x00000000, 0x01010004
    };

    private static final int[] SP2 = {
        0x80108020, 0x80008000, 0x00008000, 0x00108020,
        0x00100000, 0x00000020, 0x80100020, 0x80008020,
        0x80000020, 0x80108020, 0x80108000, 0x80000000,
        0x80008000, 0x00100000, 0x00000020, 0x80100020,
        0x00108000, 0x00100020, 0x80008020, 0x00000000,
        0x80000000, 0x00008000, 0x00108020, 0x80100000,
        0x00100020, 0x80000020, 0x00000000, 0x00108000,
        0x00008020, 0x80108000, 0x80100000, 0x00008020,
        0x00000000, 0x00108020, 0x80100020, 0x00100000,
        0x80008020, 0x80100000, 0x80108000, 0x00008000,
        0x80100000, 0x80008000, 0x00000020, 0x80108020,
        0x00108020, 0x00000020, 0x00008000, 0x80000000,
        0x00008020, 0x80108000, 0x00100000, 0x80000020,
        0x00100020, 0x80008020, 0x80000020, 0x00100020,
        0x00108000, 0x00000000, 0x80008000, 0x00008020,
        0x80000000, 0x80100020, 0x80108020, 0x00108000
    };

    private static final int[] SP3 = {
        0x00000208, 0x08020200, 0x00000000, 0x08020008,
        0x08000200, 0x00000000, 0x00020208, 0x08000200,
        0x00020008, 0x08000008, 0x08000008, 0x00020000,
        0x08020208, 0x00020008, 0x08020000, 0x00000208,
        0x08000000, 0x00000008, 0x08020200, 0x00000200,
        0x00020200, 0x08020000, 0x08020008, 0x00020208,
        0x08000208, 0x00020200, 0x00020000, 0x08000208,
        0x00000008, 0x08020208, 0x00000200, 0x08000000,
        0x08020200, 0x08000000, 0x00020008, 0x00000208,
        0x00020000, 0x08020200, 0x08000200, 0x00000000,
        0x00000200, 0x00020008, 0x08020208, 0x08000200,
        0x08000008, 0x00000200, 0x00000000, 0x08020008,
        0x08000208, 0x00020000, 0x08000000, 0x08020208,
        0x00000008, 0x00020208, 0x00020200, 0x08000008,
        0x08020000, 0x08000208, 0x00000208, 0x08020000,
        0x00020208, 0x00000008, 0x08020008, 0x00020200
    };

    private static final int[] SP4 = {
        0x00802001, 0x00002081, 0x00002081, 0x00000080,
        0x00802080, 0x00800081, 0x00800001, 0x00002001,
        0x00000000, 0x00802000, 0x00802000, 0x00802081,
        0x00000081, 0x00000000, 0x00800080, 0x00800001,
        0x00000001, 0x00002000, 0x00800000, 0x00802001,
        0x00000080, 0x00800000, 0x00002001, 0x00002080,
        0x00800081, 0x00000001, 0x00002080, 0x00800080,
        0x00002000, 0x00802080, 0x00802081, 0x00000081,
        0x00800080, 0x00800001, 0x00802000, 0x00802081,
        0x00000081, 0x00000000, 0x00000000, 0x00802000,
        0x00002080, 0x00800080, 0x00800081, 0x00000001,
        0x00802001, 0x00002081, 0x00002081, 0x00000080,
        0x00802081, 0x00000081, 0x00000001, 0x00002000,
        0x00800001, 0x00002001, 0x00802080, 0x00800081,
        0x00002001, 0x00002080, 0x00800000, 0x00802001,
        0x00000080, 0x00800000, 0x00002000, 0x00802080
    };

    private static final int[] SP5 = {
        0x00000100, 0x02080100, 0x02080000, 0x42000100,
        0x00080000, 0x00000100, 0x40000000, 0x02080000,
        0x40080100, 0x00080000, 0x02000100, 0x40080100,
        0x42000100, 0x42080000, 0x00080100, 0x40000000,
        0x02000000, 0x40080000, 0x40080000, 0x00000000,
        0x40000100, 0x42080100, 0x42080100, 0x02000100,
        0x42080000, 0x40000100, 0x00000000, 0x42000000,
        0x02080100, 0x02000000, 0x42000000, 0x00080100,
        0x00080000, 0x42000100, 0x00000100, 0x02000000,
        0x40000000, 0x02080000, 0x42000100, 0x40080100,
        0x02000100, 0x40000000, 0x42080000, 0x02080100,
        0x40080100, 0x00000100, 0x02000000, 0x42080000,
        0x42080100, 0x00080100, 0x42000000, 0x42080100,
        0x02080000, 0x00000000, 0x40080000, 0x42000000,
        0x00080100, 0x02000100, 0x40000100, 0x00080000,
        0x00000000, 0x40080000, 0x02080100, 0x40000100
    };

    private static final int[] SP6 = {
        0x20000010, 0x20400000, 0x00004000, 0x20404010,
        0x20400000, 0x00000010, 0x20404010, 0x00400000,
        0x20004000, 0x00404010, 0x00400000, 0x20000010,
        0x00400010, 0x20004000, 0x20000000, 0x00004010,
        0x00000000, 0x00400010, 0x20004010, 0x00004000,
        0x00404000, 0x20004010, 0x00000010, 0x20400010,
        0x20400010, 0x00000000, 0x00404010, 0x20404000,
        0x00004010, 0x00404000, 0x20404000, 0x20000000,
        0x20004000, 0x00000010, 0x20400010, 0x00404000,
        0x20404010, 0x00400000, 0x00004010, 0x20000010,
        0x00400000, 0x20004000, 0x20000000, 0x00004010,
        0x20000010, 0x20404010, 0x00404000, 0x20400000,
        0x00404010, 0x20404000, 0x00000000, 0x20400010,
        0x00000010, 0x00004000, 0x20400000, 0x00404010,
        0x00004000, 0x00400010, 0x20004010, 0x00000000,
        0x20404000, 0x20000000, 0x00400010, 0x20004010
    };

    private static final int[] SP7 = {
        0x00200000, 0x04200002, 0x04000802, 0x00000000,
        0x00000800, 0x04000802, 0x00200802, 0x04200800,
        0x04200802, 0x00200000, 0x00000000, 0x04000002,
        0x00000002, 0x04000000, 0x04200002, 0x00000802,
        0x04000800, 0x00200802, 0x00200002, 0x04000800,
        0x04000002, 0x04200000, 0x04200800, 0x00200002,
        0x04200000, 0x00000800, 0x00000802, 0x04200802,
        0x00200800, 0x00000002, 0x04000000, 0x00200800,
        0x04000000, 0x00200800, 0x00200000, 0x04000802,
        0x04000802, 0x04200002, 0x04200002, 0x00000002,
        0x00200002, 0x04000000, 0x04000800, 0x00200000,
        0x04200800, 0x00000802, 0x00200802, 0x04200800,
        0x00000802, 0x04000002, 0x04200802, 0x04200000,
        0x00200800, 0x00000000, 0x00000002, 0x04200802,
        0x00000000, 0x00200802, 0x04200000, 0x00000800,
        0x04000002, 0x04000800, 0x00000800, 0x00200002
    };

    private static final int[] SP8 = {
        0x10001040, 0x00001000, 0x00040000, 0x10041040,
        0x10000000, 0x10001040, 0x00000040, 0x10000000,
        0x00040040, 0x10040000, 0x10041040, 0x00041000,
        0x10041000, 0x00041040, 0x00001000, 0x00000040,
        0x10040000, 0x10000040, 0x10001000, 0x00001040,
        0x00041000, 0x00040040, 0x10040040, 0x10041000,
        0x00001040, 0x00000000, 0x00000000, 0x10040040,
        0x10000040, 0x10001000, 0x00041040, 0x00040000,
        0x00041040, 0x00040000, 0x10041000, 0x00001000,
        0x00000040, 0x10040040, 0x00001000, 0x00041040,
        0x10001000, 0x00000040, 0x10000040, 0x10040000,
        0x10040040, 0x10000000, 0x00040000, 0x10001040,
        0x00000000, 0x10041040, 0x00040040, 0x10000040,
        0x10040000, 0x10001000, 0x10001040, 0x00000000,
        0x10041040, 0x00041000, 0x00041000, 0x00001040,
        0x00001040, 0x00040040, 0x10000000, 0x10041000
    };

    /**
     * generate an integer based working key based on our secret key
     * and what we processing we are planning to do.
     *
     * Acknowledgements for this routine go to James Gillogly & Phil Karn.
     *         (whoever, and wherever they are!).
     */
    protected int[] generateWorkingKey(
        boolean encrypting,
        byte[]  key)
    {
        int[]       newKey = new int[32];
        boolean[]   pc1m = new boolean[56],
                    pcr = new boolean[56];

        for (int j = 0; j < 56; j++)
        {
            int    l = pc1[j];

            pc1m[j] = ((key[l >>> 3] & bytebit[l & 07]) != 0);
        }

        for (int i = 0; i < 16; i++)
        {
            int    l, m, n;

            if (encrypting)
            {
                m = i << 1;
            }
            else
            {
                m = (15 - i) << 1;
            }

            n = m + 1;
            newKey[m] = newKey[n] = 0;

            for (int j = 0; j < 28; j++)
            {
                l = j + totrot[i];
                if (l < 28)
                {
                    pcr[j] = pc1m[l];
                }
                else
                {
                    pcr[j] = pc1m[l - 28];
                }
            }

            for (int j = 28; j < 56; j++)
            {
                l = j + totrot[i];
                if (l < 56)
                {
                    pcr[j] = pc1m[l];
                }
                else
                {
                    pcr[j] = pc1m[l - 28];
                }
            }

            for (int j = 0; j < 24; j++)
            {
                if (pcr[pc2[j]])
                {
                    newKey[m] |= bigbyte[j];
                }

                if (pcr[pc2[j + 24]])
                {
                    newKey[n] |= bigbyte[j];
                }
            }
        }

        //
        // store the processed key
        //
        for (int i = 0; i != 32; i += 2)
        {
            int    i1, i2;

            i1 = newKey[i];
            i2 = newKey[i + 1];

            newKey[i] = ((i1 & 0x00fc0000) << 6) | ((i1 & 0x00000fc0) << 10)
                                   | ((i2 & 0x00fc0000) >>> 10) | ((i2 & 0x00000fc0) >>> 6);

            newKey[i + 1] = ((i1 & 0x0003f000) << 12) | ((i1 & 0x0000003f) << 16)
                                   | ((i2 & 0x0003f000) >>> 4) | (i2 & 0x0000003f);
        }

        return newKey;
    }

    /**
     * the DES engine.
     */
    protected void desFunc(
        int[]   wKey,
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        int     work, right, left;

        left     = (in[inOff + 0] & 0xff) << 24;
        left    |= (in[inOff + 1] & 0xff) << 16;
        left    |= (in[inOff + 2] & 0xff) << 8;
        left    |= (in[inOff + 3] & 0xff);

        right     = (in[inOff + 4] & 0xff) << 24;
        right    |= (in[inOff + 5] & 0xff) << 16;
        right    |= (in[inOff + 6] & 0xff) << 8;
        right    |= (in[inOff + 7] & 0xff);

        work = ((left >>> 4) ^ right) & 0x0f0f0f0f;
        right ^= work;
        left ^= (work << 4);
        work = ((left >>> 16) ^ right) & 0x0000ffff;
        right ^= work;
        left ^= (work << 16);
        work = ((right >>> 2) ^ left) & 0x33333333;
        left ^= work;
        right ^= (work << 2);
        work = ((right >>> 8) ^ left) & 0x00ff00ff;
        left ^= work;
        right ^= (work << 8);
        right = ((right << 1) | ((right >>> 31) & 1)) & 0xffffffff;
        work = (left ^ right) & 0xaaaaaaaa;
        left ^= work;
        right ^= work;
        left = ((left << 1) | ((left >>> 31) & 1)) & 0xffffffff;

        for (int round = 0; round < 8; round++)
        {
            int     fval;

            work  = (right << 28) | (right >>> 4);
            work ^= wKey[round * 4 + 0];
            fval  = SP7[ work      & 0x3f];
            fval |= SP5[(work >>>  8) & 0x3f];
            fval |= SP3[(work >>> 16) & 0x3f];
            fval |= SP1[(work >>> 24) & 0x3f];
            work  = right ^ wKey[round * 4 + 1];
            fval |= SP8[ work      & 0x3f];
            fval |= SP6[(work >>>  8) & 0x3f];
            fval |= SP4[(work >>> 16) & 0x3f];
            fval |= SP2[(work >>> 24) & 0x3f];
            left ^= fval;
            work  = (left << 28) | (left >>> 4);
            work ^= wKey[round * 4 + 2];
            fval  = SP7[ work      & 0x3f];
            fval |= SP5[(work >>>  8) & 0x3f];
            fval |= SP3[(work >>> 16) & 0x3f];
            fval |= SP1[(work >>> 24) & 0x3f];
            work  = left ^ wKey[round * 4 + 3];
            fval |= SP8[ work      & 0x3f];
            fval |= SP6[(work >>>  8) & 0x3f];
            fval |= SP4[(work >>> 16) & 0x3f];
            fval |= SP2[(work >>> 24) & 0x3f];
            right ^= fval;
        }

        right = (right << 31) | (right >>> 1);
        work = (left ^ right) & 0xaaaaaaaa;
        left ^= work;
        right ^= work;
        left = (left << 31) | (left >>> 1);
        work = ((left >>> 8) ^ right) & 0x00ff00ff;
        right ^= work;
        left ^= (work << 8);
        work = ((left >>> 2) ^ right) & 0x33333333;
        right ^= work;
        left ^= (work << 2);
        work = ((right >>> 16) ^ left) & 0x0000ffff;
        left ^= work;
        right ^= (work << 16);
        work = ((right >>> 4) ^ left) & 0x0f0f0f0f;
        left ^= work;
        right ^= (work << 4);

        out[outOff + 0] = (byte)((right >>> 24) & 0xff);
        out[outOff + 1] = (byte)((right >>> 16) & 0xff);
        out[outOff + 2] = (byte)((right >>>  8) & 0xff);
        out[outOff + 3] = (byte)(right         & 0xff);
        out[outOff + 4] = (byte)((left >>> 24) & 0xff);
        out[outOff + 5] = (byte)((left >>> 16) & 0xff);
        out[outOff + 6] = (byte)((left >>>  8) & 0xff);
        out[outOff + 7] = (byte)(left         & 0xff);
    }
}
