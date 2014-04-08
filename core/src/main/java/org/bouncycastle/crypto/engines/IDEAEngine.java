package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A class that provides a basic International Data Encryption Algorithm (IDEA) engine.
 * <p>
 * This implementation is based on the "HOWTO: INTERNATIONAL DATA ENCRYPTION ALGORITHM"
 * implementation summary by Fauzan Mirza (F.U.Mirza@sheffield.ac.uk). (barring 1 typo at the
 * end of the mulinv function!).
 * <p>
 * It can be found at ftp://ftp.funet.fi/pub/crypt/cryptography/symmetric/idea/
 * <p>
 * Note: This algorithm was patented in the USA, Japan and Europe. These patents expired in 2011/2012. 
 */
public class IDEAEngine
    implements BlockCipher
{
    protected static final int  BLOCK_SIZE = 8;

    private int[]               workingKey = null;

    /**
     * standard constructor.
     */
    public IDEAEngine()
    {
    }

    /**
     * initialise an IDEA cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           forEncryption,
        CipherParameters  params)
    {
        if (params instanceof KeyParameter)
        {
            workingKey = generateWorkingKey(forEncryption,
                                  ((KeyParameter)params).getKey());
            return;
        }

        throw new IllegalArgumentException("invalid parameter passed to IDEA init - " + params.getClass().getName());
    }

    public String getAlgorithmName()
    {
        return "IDEA";
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
            throw new IllegalStateException("IDEA engine not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        ideaFunc(workingKey, in, inOff, out, outOff);

        return BLOCK_SIZE;
    }

    public void reset()
    {
    }

    private static final int    MASK = 0xffff;
    private static final int    BASE = 0x10001;

    private int bytesToWord(
        byte[]  in,
        int     inOff)
    {
        return ((in[inOff] << 8) & 0xff00) + (in[inOff + 1] & 0xff);
    }

    private void wordToBytes(
        int     word,
        byte[]  out,
        int     outOff)
    {
        out[outOff] = (byte)(word >>> 8);
        out[outOff + 1] = (byte)word;
    }

    /**
     * return x = x * y where the multiplication is done modulo
     * 65537 (0x10001) (as defined in the IDEA specification) and
     * a zero input is taken to be 65536 (0x10000).
     *
     * @param x the x value
     * @param y the y value
     * @return x = x * y
     */
    private int mul(
        int x,
        int y)
    {
        if (x == 0)
        {
            x = (BASE - y);
        }
        else if (y == 0)
        {
            x = (BASE - x);
        }
        else
        {
            int     p = x * y;

            y = p & MASK;
            x = p >>> 16;
            x = y - x + ((y < x) ? 1 : 0);
        }

        return x & MASK;
    }

    private void ideaFunc(
        int[]   workingKey,
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        int     x0, x1, x2, x3, t0, t1;
        int     keyOff = 0;

        x0 = bytesToWord(in, inOff);
        x1 = bytesToWord(in, inOff + 2);
        x2 = bytesToWord(in, inOff + 4);
        x3 = bytesToWord(in, inOff + 6);

        for (int round = 0; round < 8; round++)
        {
            x0 = mul(x0, workingKey[keyOff++]);
            x1 += workingKey[keyOff++];
            x1 &= MASK;
            x2 += workingKey[keyOff++];
            x2 &= MASK;
            x3 = mul(x3, workingKey[keyOff++]);

            t0 = x1;
            t1 = x2;
            x2 ^= x0;
            x1 ^= x3;

            x2 = mul(x2, workingKey[keyOff++]);
            x1 += x2;
            x1 &= MASK;

            x1 = mul(x1, workingKey[keyOff++]);
            x2 += x1;
            x2 &= MASK;

            x0 ^= x1;
            x3 ^= x2;
            x1 ^= t1;
            x2 ^= t0;
        }

        wordToBytes(mul(x0, workingKey[keyOff++]), out, outOff);
        wordToBytes(x2 + workingKey[keyOff++], out, outOff + 2);  /* NB: Order */
        wordToBytes(x1 + workingKey[keyOff++], out, outOff + 4);
        wordToBytes(mul(x3, workingKey[keyOff]), out, outOff + 6);
    }

    /**
     * The following function is used to expand the user key to the encryption
     * subkey. The first 16 bytes are the user key, and the rest of the subkey
     * is calculated by rotating the previous 16 bytes by 25 bits to the left,
     * and so on until the subkey is completed.
     */
    private int[] expandKey(
        byte[]  uKey)
    {
        int[]   key = new int[52];

        if (uKey.length < 16)
        {
            byte[]  tmp = new byte[16];

            System.arraycopy(uKey, 0, tmp, tmp.length - uKey.length, uKey.length);

            uKey = tmp;
        }

        for (int i = 0; i < 8; i++)
        {
            key[i] = bytesToWord(uKey, i * 2);
        }

        for (int i = 8; i < 52; i++)
        {
            if ((i & 7) < 6)
            {
                key[i] = ((key[i - 7] & 127) << 9 | key[i - 6] >> 7) & MASK;
            }
            else if ((i & 7) == 6)
            {
                key[i] = ((key[i - 7] & 127) << 9 | key[i - 14] >> 7) & MASK;
            }
            else
            {
                key[i] = ((key[i - 15] & 127) << 9 | key[i - 14] >> 7) & MASK;
            }
        }

        return key;
    }

    /**
     * This function computes multiplicative inverse using Euclid's Greatest
     * Common Divisor algorithm. Zero and one are self inverse.
     * <p>
     * i.e. x * mulInv(x) == 1 (modulo BASE)
     */
    private int mulInv(
        int x)
    {
        int t0, t1, q, y;
        
        if (x < 2)
        {
            return x;
        }

        t0 = 1;
        t1 = BASE / x;
        y  = BASE % x;

        while (y != 1)
        {
            q = x / y;
            x = x % y;
            t0 = (t0 + (t1 * q)) & MASK;
            if (x == 1)
            {
                return t0;
            }
            q = y / x;
            y = y % x;
            t1 = (t1 + (t0 * q)) & MASK;
        }

        return (1 - t1) & MASK;
    }

    /**
     * Return the additive inverse of x.
     * <p>
     * i.e. x + addInv(x) == 0
     */
    int addInv(
        int x)
    {
        return (0 - x) & MASK;
    }
    
    /**
     * The function to invert the encryption subkey to the decryption subkey.
     * It also involves the multiplicative inverse and the additive inverse functions.
     */
    private int[] invertKey(
        int[] inKey)
    {
        int     t1, t2, t3, t4;
        int     p = 52;                 /* We work backwards */
        int[]   key = new int[52];
        int     inOff = 0;
    
        t1 = mulInv(inKey[inOff++]);
        t2 = addInv(inKey[inOff++]);
        t3 = addInv(inKey[inOff++]);
        t4 = mulInv(inKey[inOff++]);
        key[--p] = t4;
        key[--p] = t3;
        key[--p] = t2;
        key[--p] = t1;
    
        for (int round = 1; round < 8; round++)
        {
            t1 = inKey[inOff++];
            t2 = inKey[inOff++];
            key[--p] = t2;
            key[--p] = t1;
    
            t1 = mulInv(inKey[inOff++]);
            t2 = addInv(inKey[inOff++]);
            t3 = addInv(inKey[inOff++]);
            t4 = mulInv(inKey[inOff++]);
            key[--p] = t4;
            key[--p] = t2; /* NB: Order */
            key[--p] = t3;
            key[--p] = t1;
        }

        t1 = inKey[inOff++];
        t2 = inKey[inOff++];
        key[--p] = t2;
        key[--p] = t1;
    
        t1 = mulInv(inKey[inOff++]);
        t2 = addInv(inKey[inOff++]);
        t3 = addInv(inKey[inOff++]);
        t4 = mulInv(inKey[inOff]);
        key[--p] = t4;
        key[--p] = t3;
        key[--p] = t2;
        key[--p] = t1;

        return key;
    }
    
    private int[] generateWorkingKey(
        boolean forEncryption,
        byte[]  userKey)
    {
        if (forEncryption)
        {
            return expandKey(userKey);
        }
        else
        {
            return invertKey(expandKey(userKey));
        }
    }
}
