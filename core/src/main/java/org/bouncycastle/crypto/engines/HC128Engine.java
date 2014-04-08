package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * HC-128 is a software-efficient stream cipher created by Hongjun Wu. It
 * generates keystream from a 128-bit secret key and a 128-bit initialization
 * vector.
 * <p>
 * http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
 * </p><p>
 * It is a third phase candidate in the eStream contest, and is patent-free.
 * No attacks are known as of today (April 2007). See
 *
 * http://www.ecrypt.eu.org/stream/hcp3.html
 * </p>
 */
public class HC128Engine
    implements StreamCipher
{
    private int[] p = new int[512];
    private int[] q = new int[512];
    private int cnt = 0;

    private static int f1(int x)
    {
        return rotateRight(x, 7) ^ rotateRight(x, 18)
            ^ (x >>> 3);
    }

    private static int f2(int x)
    {
        return rotateRight(x, 17) ^ rotateRight(x, 19)
            ^ (x >>> 10);
    }

    private int g1(int x, int y, int z)
    {
        return (rotateRight(x, 10) ^ rotateRight(z, 23))
            + rotateRight(y, 8);
    }

    private int g2(int x, int y, int z)
    {
        return (rotateLeft(x, 10) ^ rotateLeft(z, 23)) + rotateLeft(y, 8);
    }

    private static int rotateLeft(
        int     x,
        int     bits)
    {
        return (x << bits) | (x >>> -bits);
    }

    private static int rotateRight(
        int     x,
        int     bits)
    {
        return (x >>> bits) | (x << -bits);
    }

    private int h1(int x)
    {
        return q[x & 0xFF] + q[((x >> 16) & 0xFF) + 256];
    }

    private int h2(int x)
    {
        return p[x & 0xFF] + p[((x >> 16) & 0xFF) + 256];
    }

    private static int mod1024(int x)
    {
        return x & 0x3FF;
    }

    private static int mod512(int x)
    {
        return x & 0x1FF;
    }

    private static int dim(int x, int y)
    {
        return mod512(x - y);
    }

    private int step()
    {
        int j = mod512(cnt);
        int ret;
        if (cnt < 512)
        {
            p[j] += g1(p[dim(j, 3)], p[dim(j, 10)], p[dim(j, 511)]);
            ret = h1(p[dim(j, 12)]) ^ p[j];
        }
        else
        {
            q[j] += g2(q[dim(j, 3)], q[dim(j, 10)], q[dim(j, 511)]);
            ret = h2(q[dim(j, 12)]) ^ q[j];
        }
        cnt = mod1024(cnt + 1);
        return ret;
    }

    private byte[] key, iv;
    private boolean initialised;

    private void init()
    {
        if (key.length != 16)
        {
            throw new java.lang.IllegalArgumentException(
                "The key must be 128 bits long");
        }

        idx = 0;
        cnt = 0;

        int[] w = new int[1280];

        for (int i = 0; i < 16; i++)
        {
            w[i >> 2] |= (key[i] & 0xff) << (8 * (i & 0x3));
        }
        System.arraycopy(w, 0, w, 4, 4);

        for (int i = 0; i < iv.length && i < 16; i++)
        {
            w[(i >> 2) + 8] |= (iv[i] & 0xff) << (8 * (i & 0x3));
        }
        System.arraycopy(w, 8, w, 12, 4);

        for (int i = 16; i < 1280; i++)
        {
            w[i] = f2(w[i - 2]) + w[i - 7] + f1(w[i - 15]) + w[i - 16] + i;
        }

        System.arraycopy(w, 256, p, 0, 512);
        System.arraycopy(w, 768, q, 0, 512);

        for (int i = 0; i < 512; i++)
        {
            p[i] = step();
        }
        for (int i = 0; i < 512; i++)
        {
            q[i] = step();
        }

        cnt = 0;
    }

    public String getAlgorithmName()
    {
        return "HC-128";
    }

    /**
     * Initialise a HC-128 cipher.
     *
     * @param forEncryption whether or not we are for encryption. Irrelevant, as
     *                      encryption and decryption are the same.
     * @param params        the parameters required to set up the cipher.
     * @throws IllegalArgumentException if the params argument is
     *                                  inappropriate (ie. the key is not 128 bit long).
     */
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        CipherParameters keyParam = params;

        if (params instanceof ParametersWithIV)
        {
            iv = ((ParametersWithIV)params).getIV();
            keyParam = ((ParametersWithIV)params).getParameters();
        }
        else
        {
            iv = new byte[0];
        }

        if (keyParam instanceof KeyParameter)
        {
            key = ((KeyParameter)keyParam).getKey();
            init();
        }
        else
        {
            throw new IllegalArgumentException(
                "Invalid parameter passed to HC128 init - "
                    + params.getClass().getName());
        }

        initialised = true;
    }

    private byte[] buf = new byte[4];
    private int idx = 0;

    private byte getByte()
    {
        if (idx == 0)
        {
            int step = step();
            buf[0] = (byte)(step & 0xFF);
            step >>= 8;
            buf[1] = (byte)(step & 0xFF);
            step >>= 8;
            buf[2] = (byte)(step & 0xFF);
            step >>= 8;
            buf[3] = (byte)(step & 0xFF);
        }
        byte ret = buf[idx];
        idx = idx + 1 & 0x3;
        return ret;
    }

    public void processBytes(byte[] in, int inOff, int len, byte[] out,
                             int outOff) throws DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalStateException(getAlgorithmName()
                + " not initialised");
        }

        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + len) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        for (int i = 0; i < len; i++)
        {
            out[outOff + i] = (byte)(in[inOff + i] ^ getByte());
        }
    }

    public void reset()
    {
        init();
    }

    public byte returnByte(byte in)
    {
        return (byte)(in ^ getByte());
    }
}
