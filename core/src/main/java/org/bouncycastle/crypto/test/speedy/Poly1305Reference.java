package org.bouncycastle.crypto.test.speedy;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Poly1305 message authentication code, designed by D. J. Bernstein.
 * <p>
 * Poly1305 computes a 128-bit (16 bytes) authenticator, using a 128 bit nonce and a 256 bit key
 * consisting of a 128 bit key applied to an underlying cipher, and a 128 bit key (with 106
 * effective key bits) used in the authenticator.
 * <p>
 * This implementation is adapted from the public domain <a href="http://nacl.cr.yp.to/">nacl</a>
 * <code>ref</code> implementation, and is probably too slow for real usage.
 * 
 * @see Poly1305KeyGenerator
 */
public class Poly1305Reference
    implements Mac
{
    private static final int BLOCK_SIZE = 16;
    private static final int STATE_SIZE = BLOCK_SIZE + 1;
    private static int[] minusp = {5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252};

    private final BlockCipher cipher;

    /** Encrypted nonce */
    private final byte[] encryptedNonce = new byte[BLOCK_SIZE];

    /** Private integer r *, expanded to 17 bytes */
    private final int[] r = new int[STATE_SIZE];

    /** Accumulated authenticator value */
    private final int[] h = new int[STATE_SIZE];

    /** Temp buffer for incorporating into authenticator */
    private final int[] c = new int[STATE_SIZE];

    private final byte[] singleByte = new byte[1];

    /** Current block of buffered input */
    private final byte[] currentBlock = new byte[BLOCK_SIZE];

    /** Current offset in input buffer */
    private int currentBlockOffset = 0;

    public Poly1305Reference(BlockCipher cipher)
    {
        if (cipher.getBlockSize() != BLOCK_SIZE)
        {
            throw new IllegalArgumentException("Poly1305 requires a 128 bit block cipher.");
        }
        this.cipher = cipher;
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        final byte[] nonce;
        final byte[] key;
        if ((params instanceof ParametersWithIV) && ((ParametersWithIV)params).getParameters() instanceof KeyParameter)
        {
            nonce = ((ParametersWithIV)params).getIV();
            key = ((KeyParameter)((ParametersWithIV)params).getParameters()).getKey();
        }
        else
        {
            throw new IllegalArgumentException("Poly1305 requires a key and and IV.");
        }

        setKey(key, nonce);
        reset();
    }

    private void setKey(byte[] key, byte[] nonce)
    {
        if (nonce.length != BLOCK_SIZE)
        {
            throw new IllegalArgumentException("Poly1305 requires a 128 bit IV.");
        }
        Poly1305KeyGenerator.checkKey(key);

        // Expand private integer r
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            r[i] = key[BLOCK_SIZE + i] & 0xFF;
        }
        r[BLOCK_SIZE] = 0;

        // Calculate encrypted nonce
        final byte[] cipherKey = new byte[BLOCK_SIZE];
        System.arraycopy(key, 0, cipherKey, 0, cipherKey.length);

        cipher.init(true, new KeyParameter(cipherKey));
        cipher.processBlock(nonce, 0, this.encryptedNonce, 0);
    }

    public String getAlgorithmName()
    {
        return "Poly1305-Ref-" + cipher.getAlgorithmName();
    }

    public int getMacSize()
    {
        return BLOCK_SIZE;
    }

    public void update(byte in)
        throws IllegalStateException
    {
        singleByte[0] = in;
        update(singleByte, 0, 1);
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException,
        IllegalStateException
    {
        int copied = 0;
        while (len > copied)
        {
            if (currentBlockOffset == currentBlock.length)
            {
                processBlock();
                currentBlockOffset = 0;
            }

            int toCopy = Math.min((len - copied), currentBlock.length - currentBlockOffset);
            System.arraycopy(in, copied + inOff, currentBlock, currentBlockOffset, toCopy);
            copied += toCopy;
            currentBlockOffset += toCopy;
        }

    }

    /**
     * Add a full block of 16 bytes of data, padded to 17 bytes, to the MAC
     */
    private void processBlock()
    {
        for (int i = 0; i < currentBlockOffset; i++)
        {
            c[i] = currentBlock[i] & 0xFF;
        }
        c[currentBlockOffset] = 1;
        for (int i = currentBlockOffset + 1; i < c.length; i++)
        {
            c[i] = 0;
        }
        add(h, c);
        mulmod(h, r);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException,
        IllegalStateException
    {
        if (outOff + BLOCK_SIZE > out.length)
        {
            throw new DataLengthException("Output buffer is too short.");
        }

        if (currentBlockOffset > 0)
        {
            // Process padded final block
            processBlock();
        }

        freeze(h);

        // Add encrypted nonce to result
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            c[i] = encryptedNonce[i] & 0xFF;
        }
        c[BLOCK_SIZE] = 0;
        add(h, c);

        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            out[outOff + i] = (byte)h[i];
        }

        reset();
        return BLOCK_SIZE;
    }

    public void reset()
    {
        currentBlockOffset = 0;
        for (int i = 0; i < h.length; i++)
        {
            h[i] = 0;
        }
    }

    // 130 bit math adapted from nacl ref implementation

    /**
     * 130 bit add with carry.
     */
    private static void add(int[] h, int[] c)
    {
        int u = 0;
        for (int j = 0; j < 17; ++j)
        {
            u += h[j] + c[j];
            h[j] = u & 255;
            u >>= 8;
        }
    }

    /**
     * 130 bit multiplication mod 2^130-5
     */
    private void mulmod(int[] h, int[] r)
    {
        final int[] hr = c;

        for (int i = 0; i < 17; ++i)
        {
            int u = 0;
            /* Basic multiply to compute term i */
            for (int j = 0; j <= i; ++j)
            {
                u += h[j] * r[i - j];
            }

            /*
             * Modular reduction
             *
             * Shift overflow >> 130 bits == (>> 17 bytes = 136 bits) + (<< 6 bits = * 64)
             *
             * Reduction mod 2^130-5 leaves 5x remainder, so 64 * 5 = 320.
             */
            for (int j = i + 1; j < 17; ++j)
            {
                u += 320 * h[j] * r[i + 17 - j];
            }
            hr[i] = u;
        }
        System.arraycopy(hr, 0, h, 0, h.length);
        squeeze(h);
    }

    /**
     * Propagate carries following a modular multiplication.
     */
    private static void squeeze(int[] h)
    {
        int u = 0;
        for (int j = 0; j < 16; ++j)
        {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u & 3;
        u = 5 * (u >> 2);
        for (int j = 0; j < 16; ++j)
        {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u;
    }

    /**
     * Constant time correction of h to be &lt; p (2^130 - 5).
     */
    private void freeze(int[] h)
    {
        final int[] horig = c;
        System.arraycopy(h, 0, horig, 0, h.length);

        add(h, minusp);
        final int negative = -(h[16] >> 7);
        for (int j = 0; j < 17; ++j)
        {
            h[j] ^= negative & (horig[j] ^ h[j]);
        }
    }

}
