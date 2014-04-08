package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;

/**
 * Implements OpenPGP's rather strange version of Cipher-FeedBack (CFB) mode
 * on top of a simple cipher. This class assumes the IV has been prepended
 * to the data stream already, and just accomodates the reset after
 * (blockSize + 2) bytes have been read.
 * <p>
 * For further info see <a href="http://www.ietf.org/rfc/rfc2440.html">RFC 2440</a>.
 */
public class OpenPGPCFBBlockCipher
    implements BlockCipher
{
    private byte[] IV;
    private byte[] FR;
    private byte[] FRE;

    private BlockCipher cipher;

    private int count;
    private int blockSize;
    private boolean forEncryption;
    
    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     */
    public OpenPGPCFBBlockCipher(
        BlockCipher cipher)
    {
        this.cipher = cipher;

        this.blockSize = cipher.getBlockSize();
        this.IV = new byte[blockSize];
        this.FR = new byte[blockSize];
        this.FRE = new byte[blockSize];
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
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/PGPCFB"
     * and the block size in bits.
     */
    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/OpenPGPCFB";
    }
    
    /**
     * return the block size we are operating at.
     *
     * @return the block size we are operating at (in bytes).
     */
    public int getBlockSize()
    {
        return cipher.getBlockSize();
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
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
        throws DataLengthException, IllegalStateException
    {
        return (forEncryption) ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
    }
    
    /**
     * reset the chaining vector back to the IV and reset the underlying
     * cipher.
     */
    public void reset()
    {
        count = 0;

        System.arraycopy(IV, 0, FR, 0, FR.length);

        cipher.reset();
    }

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV).
     * If an IV isn't passed as part of the parameter, the IV will be all zeros.
     * An IV which is too short is handled in FIPS compliant fashion.
     *
     * @param forEncryption if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean forEncryption,
        CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
     
        reset();

        cipher.init(true, params);
    }
    
    /**
     * Encrypt one byte of data according to CFB mode.
     * @param data the byte to encrypt
     * @param blockOff offset in the current block
     * @return the encrypted byte
     */
    private byte encryptByte(byte data, int blockOff)
    {
        return (byte)(FRE[blockOff] ^ data);
    }
    
    /**
     * Do the appropriate processing for CFB IV mode encryption.
     *
     * @param in the array containing the data to be encrypted.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the encrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception DataLengthException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private int encryptBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
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
        
        if (count > blockSize)
        {
            FR[blockSize - 2] = out[outOff] = encryptByte(in[inOff], blockSize - 2);
            FR[blockSize - 1] = out[outOff + 1] = encryptByte(in[inOff + 1], blockSize - 1);

            cipher.processBlock(FR, 0, FRE, 0);

            for (int n = 2; n < blockSize; n++) 
            {
                FR[n - 2] = out[outOff + n] = encryptByte(in[inOff + n], n - 2);
            }
        }
        else if (count == 0)
        {
            cipher.processBlock(FR, 0, FRE, 0);

            for (int n = 0; n < blockSize; n++) 
            {
                FR[n] = out[outOff + n] = encryptByte(in[inOff + n], n);
            }
            
            count += blockSize;
        }
        else if (count == blockSize)
        {
            cipher.processBlock(FR, 0, FRE, 0);

            out[outOff] = encryptByte(in[inOff], 0);
            out[outOff + 1] = encryptByte(in[inOff + 1], 1);

            //
            // do reset
            //
            System.arraycopy(FR, 2, FR, 0, blockSize - 2);
            System.arraycopy(out, outOff, FR, blockSize - 2, 2);

            cipher.processBlock(FR, 0, FRE, 0);

            for (int n = 2; n < blockSize; n++) 
            {
                FR[n - 2] = out[outOff + n] = encryptByte(in[inOff + n], n - 2);
            }

            count += blockSize;
        }
        
        return blockSize;
    }

    /**
     * Do the appropriate processing for CFB IV mode decryption.
     *
     * @param in the array containing the data to be decrypted.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the encrypted data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception DataLengthException if there isn't enough data in in, or
     * space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private int decryptBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
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
        
        if (count > blockSize)
        {
            byte inVal = in[inOff];
            FR[blockSize - 2] = inVal;
            out[outOff] = encryptByte(inVal, blockSize - 2);

            inVal = in[inOff + 1];
            FR[blockSize - 1] = inVal;
            out[outOff + 1] = encryptByte(inVal, blockSize - 1);

            cipher.processBlock(FR, 0, FRE, 0);
            
            for (int n = 2; n < blockSize; n++) 
            {
                inVal = in[inOff + n];
                FR[n - 2] = inVal;
                out[outOff + n] = encryptByte(inVal, n - 2);
            }
        } 
        else if (count == 0)
        {
            cipher.processBlock(FR, 0, FRE, 0);
            
            for (int n = 0; n < blockSize; n++) 
            {
                FR[n] = in[inOff + n];
                out[n] = encryptByte(in[inOff + n], n);
            }
            
            count += blockSize;
        }
        else if (count == blockSize)
        {
            cipher.processBlock(FR, 0, FRE, 0);

            byte inVal1 = in[inOff];
            byte inVal2 = in[inOff + 1];
            out[outOff    ] = encryptByte(inVal1, 0);
            out[outOff + 1] = encryptByte(inVal2, 1);
            
            System.arraycopy(FR, 2, FR, 0, blockSize - 2);

            FR[blockSize - 2] = inVal1;
            FR[blockSize - 1] = inVal2;

            cipher.processBlock(FR, 0, FRE, 0);

            for (int n = 2; n < blockSize; n++) 
            {
                byte inVal = in[inOff + n];
                FR[n - 2] = inVal;
                out[outOff + n] = encryptByte(inVal, n - 2);
            }

            count += blockSize;
        }
        
        return blockSize;
    }
}
