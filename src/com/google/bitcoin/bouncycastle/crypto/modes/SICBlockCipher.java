package com.google.bitcoin.bouncycastle.crypto.modes;

import com.google.bitcoin.bouncycastle.crypto.BlockCipher;
import com.google.bitcoin.bouncycastle.crypto.CipherParameters;
import com.google.bitcoin.bouncycastle.crypto.DataLengthException;
import com.google.bitcoin.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Implements the Segmented Integer Counter (SIC) mode on top of a simple
 * block cipher. This mode is also known as CTR mode.
 */
public class SICBlockCipher implements BlockCipher
{
    private final BlockCipher     cipher;
    private final int             blockSize;
    
    private byte[]          IV;
    private byte[]          counter;
    private byte[]          counterOut;


    /**
     * Basic constructor.
     *
     * @param c the block cipher to be used.
     */
    public SICBlockCipher(BlockCipher c)
    {
        this.cipher = c;
        this.blockSize = cipher.getBlockSize();
        this.IV = new byte[blockSize];
        this.counter = new byte[blockSize];
        this.counterOut = new byte[blockSize];
    }


    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }


    public void init(
        boolean             forEncryption, //ignored by this CTR mode
        CipherParameters    params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
          ParametersWithIV ivParam = (ParametersWithIV)params;
          byte[]           iv      = ivParam.getIV();
          System.arraycopy(iv, 0, IV, 0, IV.length);

          reset();
          cipher.init(true, ivParam.getParameters());
        }
        else
        {
            throw new IllegalArgumentException("SIC mode requires ParametersWithIV");
        }
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/SIC";
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }


    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
          throws DataLengthException, IllegalStateException
    {
        cipher.processBlock(counter, 0, counterOut, 0);

        //
        // XOR the counterOut with the plaintext producing the cipher text
        //
        for (int i = 0; i < counterOut.length; i++)
        {
          out[outOff + i] = (byte)(counterOut[i] ^ in[inOff + i]);
        }

        int    carry = 1;
        
        for (int i = counter.length - 1; i >= 0; i--)
        {
            int    x = (counter[i] & 0xff) + carry;
            
            if (x > 0xff)
            {
                carry = 1;
            }
            else
            {
                carry = 0;
            }
            
            counter[i] = (byte)x;
        }

        return counter.length;
    }


    public void reset()
    {
        System.arraycopy(IV, 0, counter, 0, counter.length);
        cipher.reset();
    }
}
