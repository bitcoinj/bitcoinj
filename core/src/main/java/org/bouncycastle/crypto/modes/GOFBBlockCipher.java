package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * implements the GOST 28147 OFB counter mode (GCTR).
 */
public class GOFBBlockCipher
    implements BlockCipher
{
    private byte[]          IV;
    private byte[]          ofbV;
    private byte[]          ofbOutV;

    private final int             blockSize;
    private final BlockCipher     cipher;

    boolean firstStep = true;
    int N3;
    int N4;
    static final int C1 = 16843012; //00000001000000010000000100000100
    static final int C2 = 16843009; //00000001000000010000000100000001


    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * counter mode (must have a 64 bit block size).
     */
    public GOFBBlockCipher(
        BlockCipher cipher)
    {
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        
        if (blockSize != 8)
        {
            throw new IllegalArgumentException("GCTR only for 64 bit block ciphers");
        }

        this.IV = new byte[cipher.getBlockSize()];
        this.ofbV = new byte[cipher.getBlockSize()];
        this.ofbOutV = new byte[cipher.getBlockSize()];
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

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     * An IV which is too short is handled in FIPS compliant fashion.
     *
     * @param encrypting if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             encrypting, //ignored by this CTR mode
        CipherParameters    params)
        throws IllegalArgumentException
    {
        firstStep = true;
        N3 = 0;
        N4 = 0;

        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            byte[] iv = ivParam.getIV();

            if (iv.length < IV.length)
            {
                // prepend the supplied IV with zeros (per FIPS PUB 81)
                System.arraycopy(iv, 0, IV, IV.length - iv.length, iv.length);
                for (int i = 0; i < IV.length - iv.length; i++)
                {
                    IV[i] = 0;
                }
            }
            else
            {
                System.arraycopy(iv, 0, IV, 0, IV.length);
            }

            reset();

            // if params is null we reuse the current working key.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }
        }
        else
        {
            reset();

            // if params is null we reuse the current working key.
            if (params != null)
            {
                cipher.init(true, params);
            }
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/GCTR"
     * and the block size in bits
     */
    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/GCTR";
    }

    
    /**
     * return the block size we are operating at (in bytes).
     *
     * @return the block size we are operating at (in bytes).
     */
    public int getBlockSize()
    {
        return blockSize;
    }

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param in the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception DataLengthException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    public int processBlock(
        byte[]      in,
        int         inOff,
        byte[]      out,
        int         outOff)
        throws DataLengthException, IllegalStateException
    {
        if ((inOff + blockSize) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + blockSize) > out.length)
        {
            throw new DataLengthException("output buffer too short");
        }

        if (firstStep)
        {
            firstStep = false;
            cipher.processBlock(ofbV, 0, ofbOutV, 0);
            N3 = bytesToint(ofbOutV, 0);
            N4 = bytesToint(ofbOutV, 4);
        }
        N3 += C2;
        N4 += C1;
        intTobytes(N3, ofbV, 0);
        intTobytes(N4, ofbV, 4);

        cipher.processBlock(ofbV, 0, ofbOutV, 0);

        //
        // XOR the ofbV with the plaintext producing the cipher text (and
        // the next input block).
        //
        for (int i = 0; i < blockSize; i++)
        {
            out[outOff + i] = (byte)(ofbOutV[i] ^ in[inOff + i]);
        }

        //
        // change over the input block.
        //
        System.arraycopy(ofbV, blockSize, ofbV, 0, ofbV.length - blockSize);
        System.arraycopy(ofbOutV, 0, ofbV, ofbV.length - blockSize, blockSize);

        return blockSize;
    }

    /**
     * reset the feedback vector back to the IV and reset the underlying
     * cipher.
     */
    public void reset()
    {
        firstStep = true;
        N3 = 0;
        N4 = 0;
        System.arraycopy(IV, 0, ofbV, 0, IV.length);

        cipher.reset();
    }

    //array of bytes to type int
    private int bytesToint(
        byte[]  in,
        int     inOff)
    {
        return  ((in[inOff + 3] << 24) & 0xff000000) + ((in[inOff + 2] << 16) & 0xff0000) +
                ((in[inOff + 1] << 8) & 0xff00) + (in[inOff] & 0xff);
    }

    //int to array of bytes
    private void intTobytes(
            int     num,
            byte[]  out,
            int     outOff)
    {
            out[outOff + 3] = (byte)(num >>> 24);
            out[outOff + 2] = (byte)(num >>> 16);
            out[outOff + 1] = (byte)(num >>> 8);
            out[outOff] =     (byte)num;
    }
}
