package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithSBox;

/**
 * An implementation of the GOST CFB mode with CryptoPro key meshing as described in RFC 4357.
 */
public class GCFBBlockCipher
    implements BlockCipher
{
    private static final byte[] C =
        {
            0x69, 0x00, 0x72, 0x22, 0x64, (byte)0xC9, 0x04, 0x23,
            (byte)0x8D, 0x3A, (byte)0xDB, (byte)0x96, 0x46, (byte)0xE9, 0x2A, (byte)0xC4,
            0x18, (byte)0xFE, (byte)0xAC, (byte)0x94, 0x00, (byte)0xED, 0x07, 0x12,
            (byte)0xC0, (byte)0x86, (byte)0xDC, (byte)0xC2, (byte)0xEF, 0x4C, (byte)0xA9, 0x2B
        };

    private final CFBBlockCipher cfbEngine;

    private KeyParameter key;
    private long         counter = 0;
    private boolean      forEncryption;

    public GCFBBlockCipher(BlockCipher engine)
    {
        this.cfbEngine = new CFBBlockCipher(engine, engine.getBlockSize() * 8);
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        counter = 0;
        cfbEngine.init(forEncryption, params);

        this.forEncryption = forEncryption;

        if (params instanceof ParametersWithIV)
        {
            params = ((ParametersWithIV)params).getParameters();
        }

        if (params instanceof ParametersWithRandom)
        {
            params = ((ParametersWithRandom)params).getParameters();
        }

        if (params instanceof ParametersWithSBox)
        {
            params = ((ParametersWithSBox)params).getParameters();
        }

        key = (KeyParameter)params;
    }

    public String getAlgorithmName()
    {
        return "G" + cfbEngine.getAlgorithmName();
    }

    public int getBlockSize()
    {
        return cfbEngine.getBlockSize();
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (counter > 0 && counter % 1024 == 0)
        {
            BlockCipher  base = cfbEngine.getUnderlyingCipher();

            base.init(false, key);

            byte[] nextKey = new byte[32];

            base.processBlock(C, 0, nextKey, 0);
            base.processBlock(C, 8, nextKey, 8);
            base.processBlock(C, 16, nextKey, 16);
            base.processBlock(C, 24, nextKey, 24);

            key = new KeyParameter(nextKey);

            byte[] iv = new byte[8];

            base.init(true, key);

            base.processBlock(cfbEngine.getCurrentIV(), 0, iv, 0);

            cfbEngine.init(forEncryption, new ParametersWithIV(key, iv));
        }

        counter += cfbEngine.getBlockSize();

        return cfbEngine.processBlock(in, inOff, out, outOff);
    }

    public void reset()
    {
        counter = 0;
        cfbEngine.reset();
    }
}
