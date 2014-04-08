package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * implements a Cipher-FeedBack (CFB) mode on top of a simple cipher.
 */
class MacCFBBlockCipher
{
    private byte[]          IV;
    private byte[]          cfbV;
    private byte[]          cfbOutV;

    private int                 blockSize;
    private BlockCipher         cipher = null;

    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     * @param blockSize the block size in bits (note: a multiple of 8)
     */
    public MacCFBBlockCipher(
        BlockCipher         cipher,
        int                 bitBlockSize)
    {
        this.cipher = cipher;
        this.blockSize = bitBlockSize / 8;

        this.IV = new byte[cipher.getBlockSize()];
        this.cfbV = new byte[cipher.getBlockSize()];
        this.cfbOutV = new byte[cipher.getBlockSize()];
    }

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     * An IV which is too short is handled in FIPS compliant fashion.
     *
     * @param param the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        CipherParameters    params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
                ParametersWithIV ivParam = (ParametersWithIV)params;
                byte[]      iv = ivParam.getIV();

                if (iv.length < IV.length)
                {
                    System.arraycopy(iv, 0, IV, IV.length - iv.length, iv.length);
                }
                else
                {
                    System.arraycopy(iv, 0, IV, 0, IV.length);
                }

                reset();

                cipher.init(true, ivParam.getParameters());
        }
        else
        {
                reset();

                cipher.init(true, params);
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/CFB"
     * and the block size in bits.
     */
    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
    }

    /**
     * return the block size we are operating at.
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

        cipher.processBlock(cfbV, 0, cfbOutV, 0);

        //
        // XOR the cfbV with the plaintext producing the cipher text
        //
        for (int i = 0; i < blockSize; i++)
        {
            out[outOff + i] = (byte)(cfbOutV[i] ^ in[inOff + i]);
        }

        //
        // change over the input block.
        //
        System.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.length - blockSize);
        System.arraycopy(out, outOff, cfbV, cfbV.length - blockSize, blockSize);

        return blockSize;
    }

    /**
     * reset the chaining vector back to the IV and reset the underlying
     * cipher.
     */
    public void reset()
    {
        System.arraycopy(IV, 0, cfbV, 0, IV.length);

        cipher.reset();
    }

    void getMacBlock(
        byte[]  mac)
    {
        cipher.processBlock(cfbV, 0, mac, 0);
    }
}

public class CFBBlockCipherMac
    implements Mac
{
    private byte[]              mac;

    private byte[]              buf;
    private int                 bufOff;
    private MacCFBBlockCipher   cipher;
    private BlockCipherPadding  padding = null;


    private int                 macSize;

    /**
     * create a standard MAC based on a CFB block cipher. This will produce an
     * authentication code half the length of the block size of the cipher, with
     * the CFB mode set to 8 bits.
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     */
    public CFBBlockCipherMac(
        BlockCipher     cipher)
    {
        this(cipher, 8, (cipher.getBlockSize() * 8) / 2, null);
    }

    /**
     * create a standard MAC based on a CFB block cipher. This will produce an
     * authentication code half the length of the block size of the cipher, with
     * the CFB mode set to 8 bits.
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param padding the padding to be used.
     */
    public CFBBlockCipherMac(
        BlockCipher         cipher,
        BlockCipherPadding  padding)
    {
        this(cipher, 8, (cipher.getBlockSize() * 8) / 2, padding);
    }

    /**
     * create a standard MAC based on a block cipher with the size of the
     * MAC been given in bits. This class uses CFB mode as the basis for the
     * MAC generation.
     * <p>
     * Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
     * or 16 bits if being used as a data authenticator (FIPS Publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see Handbook of Applied Cryptography).
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param cfbBitSize the size of an output block produced by the CFB mode.
     * @param macSizeInBits the size of the MAC in bits, must be a multiple of 8.
     */
    public CFBBlockCipherMac(
        BlockCipher         cipher,
        int                 cfbBitSize,
        int                 macSizeInBits)
    {
        this(cipher, cfbBitSize, macSizeInBits, null);
    }

    /**
     * create a standard MAC based on a block cipher with the size of the
     * MAC been given in bits. This class uses CFB mode as the basis for the
     * MAC generation.
     * <p>
     * Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
     * or 16 bits if being used as a data authenticator (FIPS Publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see Handbook of Applied Cryptography).
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param cfbBitSize the size of an output block produced by the CFB mode.
     * @param macSizeInBits the size of the MAC in bits, must be a multiple of 8.
     * @param padding a padding to be used.
     */
    public CFBBlockCipherMac(
        BlockCipher         cipher,
        int                 cfbBitSize,
        int                 macSizeInBits,
        BlockCipherPadding  padding)
    {
        if ((macSizeInBits % 8) != 0)
        {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        }

        mac = new byte[cipher.getBlockSize()];

        this.cipher = new MacCFBBlockCipher(cipher, cfbBitSize);
        this.padding = padding;
        this.macSize = macSizeInBits / 8;

        buf = new byte[this.cipher.getBlockSize()];
        bufOff = 0;
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName();
    }

    public void init(
        CipherParameters    params)
    {
        reset();

        cipher.init(params);
    }

    public int getMacSize()
    {
        return macSize;
    }

    public void update(
        byte        in)
    {
        if (bufOff == buf.length)
        {
            cipher.processBlock(buf, 0, mac, 0);
            bufOff = 0;
        }

        buf[bufOff++] = in;
    }

    public void update(
        byte[]      in,
        int         inOff,
        int         len)
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        int blockSize = cipher.getBlockSize();
        int resultLen = 0;
        int gapLen = blockSize - bufOff;

        if (len > gapLen)
        {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            resultLen += cipher.processBlock(buf, 0, mac, 0);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize)
            {
                resultLen += cipher.processBlock(in, inOff, mac, 0);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;
    }

    public int doFinal(
        byte[]  out,
        int     outOff)
    {
        int blockSize = cipher.getBlockSize();

        //
        // pad with zeroes
        //
        if (this.padding == null)
        {
            while (bufOff < blockSize)
            {
                buf[bufOff] = 0;
                bufOff++;
            }
        }
        else
        {
            padding.addPadding(buf, bufOff);
        }

        cipher.processBlock(buf, 0, mac, 0);

        cipher.getMacBlock(mac);

        System.arraycopy(mac, 0, out, outOff, macSize);

        reset();

        return macSize;
    }

    /**
     * Reset the mac generator.
     */
    public void reset()
    {
        /*
         * clean the buffer.
         */
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] = 0;
        }

        bufOff = 0;

        /*
         * reset the underlying cipher.
         */
        cipher.reset();
    }
}
