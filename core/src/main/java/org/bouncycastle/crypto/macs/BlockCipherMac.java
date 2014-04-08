package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;

public class BlockCipherMac
    implements Mac
{
    private byte[]          mac;

    private byte[]          buf;
    private int             bufOff;
    private BlockCipher     cipher;

    private int             macSize;

    /**
     * create a standard MAC based on a block cipher. This will produce an
     * authentication code half the length of the block size of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @deprecated use CBCBlockCipherMac
     */
    public BlockCipherMac(
        BlockCipher     cipher)
    {
        this(cipher, (cipher.getBlockSize() * 8) / 2);
    }

    /**
     * create a standard MAC based on a block cipher with the size of the
     * MAC been given in bits.
     * <p>
     * Note: the size of the MAC must be at least 16 bits (FIPS Publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see Handbook of Applied Cryptography).
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param macSizeInBits the size of the MAC in bits, must be a multiple of 8.
     * @deprecated use CBCBlockCipherMac
     */
    public BlockCipherMac(
        BlockCipher     cipher,
        int             macSizeInBits)
    {
        if ((macSizeInBits % 8) != 0)
        {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        }

        this.cipher = new CBCBlockCipher(cipher);
        this.macSize = macSizeInBits / 8;

        mac = new byte[cipher.getBlockSize()];

        buf = new byte[cipher.getBlockSize()];
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

        cipher.init(true, params);
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
        while (bufOff < blockSize)
        {
            buf[bufOff] = 0;
            bufOff++;
        }

        cipher.processBlock(buf, 0, mac, 0);

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
