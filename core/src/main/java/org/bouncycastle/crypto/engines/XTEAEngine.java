package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * An XTEA engine.
 */
public class XTEAEngine
    implements BlockCipher
{
    private static final int rounds     = 32,
                             block_size = 8,
//                             key_size   = 16,
                             delta      = 0x9E3779B9;

    /*
     * the expanded key array of 4 subkeys
     */
    private int[]   _S    = new int[4],
                    _sum0 = new int[32],
                    _sum1 = new int[32];
    private boolean _initialised,
                    _forEncryption;

    /**
     * Create an instance of the TEA encryption algorithm
     * and set some defaults
     */
    public XTEAEngine()
    {
        _initialised = false;
    }

    public String getAlgorithmName()
    {
        return "XTEA";
    }

    public int getBlockSize()
    {
        return block_size;
    }

    /**
     * initialise
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             forEncryption,
        CipherParameters    params)
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException("invalid parameter passed to TEA init - " + params.getClass().getName());
        }

        _forEncryption = forEncryption;
        _initialised = true;

        KeyParameter       p = (KeyParameter)params;

        setKey(p.getKey());
    }

    public int processBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        if (!_initialised)
        {
            throw new IllegalStateException(getAlgorithmName()+" not initialised");
        }

        if ((inOff + block_size) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + block_size) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        return (_forEncryption) ? encryptBlock(in, inOff, out, outOff)
                                    : decryptBlock(in, inOff, out, outOff);
    }

    public void reset()
    {
    }

    /**
     * Re-key the cipher.
     * <p>
     * @param  key  the key to be used
     */
    private void setKey(
        byte[]      key)
    {
        if (key.length != 16) 
        {
            throw new IllegalArgumentException("Key size must be 128 bits.");
        }

        int i, j;
        for (i = j = 0; i < 4; i++,j+=4)
        {
            _S[i] = bytesToInt(key, j);
        }
            
        for (i = j = 0; i < rounds; i++)
        {
                _sum0[i] = (j + _S[j & 3]);
                j += delta;
                _sum1[i] = (j + _S[j >>> 11 & 3]);
        }
    }

    private int encryptBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        // Pack bytes into integers
        int v0 = bytesToInt(in, inOff);
        int v1 = bytesToInt(in, inOff + 4);

        for (int i = 0; i < rounds; i++)
        {
            v0    += ((v1 << 4 ^ v1 >>> 5) + v1) ^ _sum0[i];
            v1    += ((v0 << 4 ^ v0 >>> 5) + v0) ^ _sum1[i];
        }

        unpackInt(v0, out, outOff);
        unpackInt(v1, out, outOff + 4);

        return block_size;
    }

    private int decryptBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        // Pack bytes into integers
        int v0 = bytesToInt(in, inOff);
        int v1 = bytesToInt(in, inOff + 4);

        for (int i = rounds-1; i >= 0; i--)
        {
            v1  -= ((v0 << 4 ^ v0 >>> 5) + v0) ^ _sum1[i];
            v0  -= ((v1 << 4 ^ v1 >>> 5) + v1) ^ _sum0[i];
        }

        unpackInt(v0, out, outOff);
        unpackInt(v1, out, outOff + 4);

        return block_size;
    }

    private int bytesToInt(byte[] in, int inOff)
    {
        return ((in[inOff++]) << 24) |
                 ((in[inOff++] & 255) << 16) |
                 ((in[inOff++] & 255) <<  8) |
                 ((in[inOff] & 255));
    }

    private void unpackInt(int v, byte[] out, int outOff)
    {
        out[outOff++] = (byte)(v >>> 24);
        out[outOff++] = (byte)(v >>> 16);
        out[outOff++] = (byte)(v >>>  8);
        out[outOff  ] = (byte)v;
    }
}
