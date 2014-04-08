package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Implements OpenPGP's rather strange version of Cipher-FeedBack (CFB) mode on top of a simple cipher. For further info see <a href="http://www.ietf.org/rfc/rfc2440.html">RFC 2440</a>.
 */
public class PGPCFBBlockCipher
    implements BlockCipher
{
    private byte[] IV;
    private byte[] FR;
    private byte[] FRE;
    private byte[] tmp;

    private BlockCipher cipher;

    private int count;
    private int blockSize;
    private boolean forEncryption;
    
    private boolean inlineIv; // if false we don't need to prepend an IV

    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     * @param inlineIv if true this is for PGP CFB with a prepended iv.
     */
    public PGPCFBBlockCipher(
        BlockCipher cipher,
        boolean     inlineIv)
    {
        this.cipher = cipher;
        this.inlineIv = inlineIv;

        this.blockSize = cipher.getBlockSize();
        this.IV = new byte[blockSize];
        this.FR = new byte[blockSize];
        this.FRE = new byte[blockSize];
        this.tmp = new byte[blockSize];
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
        if (inlineIv)
        {
            return cipher.getAlgorithmName() + "/PGPCFBwithIV";
        }
        else
        {
            return cipher.getAlgorithmName() + "/PGPCFB";
        }
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
        if (inlineIv)
        {
            return (forEncryption) ? encryptBlockWithIV(in, inOff, out, outOff) : decryptBlockWithIV(in, inOff, out, outOff);
        }
        else
        {
            return (forEncryption) ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
        }
    }
    
    /**
     * reset the chaining vector back to the IV and reset the underlying
     * cipher.
     */
    public void reset()
    {
        count = 0;

        for (int i = 0; i != FR.length; i++)
        {
            if (inlineIv)
            {
                FR[i] = 0;
            }
            else
            {
                FR[i] = IV[i]; // if simple mode, key is IV (even if this is zero)
            }
        }

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
     
        if (params instanceof ParametersWithIV)
        {
                ParametersWithIV ivParam = (ParametersWithIV)params;
                byte[]      iv = ivParam.getIV();

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

                cipher.init(true, ivParam.getParameters());
        }
        else
        {
                reset();

                cipher.init(true, params);
        }
    }
    
    /**
     * Encrypt one byte of data according to CFB mode.
     * @param data the byte to encrypt
     * @param blockOff where am i in the current block, determines when to resync the block
     * @returns the encrypted byte
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
    private int encryptBlockWithIV(
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

        if (count == 0)
        {
            if ((outOff + 2 * blockSize + 2) > out.length)
            {
                throw new DataLengthException("output buffer too short");
            }

            cipher.processBlock(FR, 0, FRE, 0);

            for (int n = 0; n < blockSize; n++) 
            {
                out[outOff + n] = encryptByte(IV[n], n);
            }
            
            System.arraycopy(out, outOff, FR, 0, blockSize);

            cipher.processBlock(FR, 0, FRE, 0);

            out[outOff + blockSize] = encryptByte(IV[blockSize - 2], 0);
            out[outOff + blockSize + 1] = encryptByte(IV[blockSize - 1], 1);

            System.arraycopy(out, outOff + 2, FR, 0, blockSize);
            
            cipher.processBlock(FR, 0, FRE, 0);

            for (int n = 0; n < blockSize; n++) 
            {
                out[outOff + blockSize + 2 + n] = encryptByte(in[inOff + n], n);
            }

            System.arraycopy(out, outOff + blockSize + 2, FR, 0, blockSize);

            count += 2 * blockSize + 2;

            return 2 * blockSize + 2;
        }
        else if (count >= blockSize + 2)
        {
            if ((outOff + blockSize) > out.length)
            {
                throw new DataLengthException("output buffer too short");
            }

            cipher.processBlock(FR, 0, FRE, 0);

            for (int n = 0; n < blockSize; n++) 
            {
                out[outOff + n] = encryptByte(in[inOff + n], n);
            }
            
            System.arraycopy(out, outOff, FR, 0, blockSize);
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
    private int decryptBlockWithIV(
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
        
        if (count == 0)
        {
            for (int n = 0; n < blockSize; n++) 
            {
                FR[n] = in[inOff + n];
            }
            
            cipher.processBlock(FR, 0, FRE, 0);

            count += blockSize;

            return 0;
        }
        else if (count == blockSize)
        {
            // copy in buffer so that this mode works if in and out are the same 
            System.arraycopy(in, inOff, tmp, 0, blockSize);
        
            System.arraycopy(FR, 2, FR, 0, blockSize - 2);
            
            FR[blockSize - 2] = tmp[0];
            FR[blockSize - 1] = tmp[1];

            cipher.processBlock(FR, 0, FRE, 0);

            for (int n = 0; n < blockSize - 2; n++) 
            {
                out[outOff + n] = encryptByte(tmp[n + 2], n);
            }

            System.arraycopy(tmp, 2, FR, 0, blockSize - 2);

            count += 2;

            return blockSize - 2;
        }
        else if (count >= blockSize + 2)
        {
            // copy in buffer so that this mode works if in and out are the same 
            System.arraycopy(in, inOff, tmp, 0, blockSize);

            out[outOff + 0] = encryptByte(tmp[0], blockSize - 2);
            out[outOff + 1] = encryptByte(tmp[1], blockSize - 1);

            System.arraycopy(tmp, 0, FR, blockSize - 2, 2);

            cipher.processBlock(FR, 0, FRE, 0);
            
            for (int n = 0; n < blockSize - 2; n++) 
            {
                out[outOff + n + 2] = encryptByte(tmp[n + 2], n);
            }
            
            System.arraycopy(tmp, 2, FR, 0, blockSize - 2);
            
        } 
        
        return blockSize;
    }
    
    /**
     * Do the appropriate processing for CFB mode encryption.
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
        
        cipher.processBlock(FR, 0, FRE, 0);
        for (int n = 0; n < blockSize; n++) 
        {
            out[outOff + n] = encryptByte(in[inOff + n], n);
        }
        
        for (int n = 0; n < blockSize; n++) 
        {
            FR[n] = out[outOff + n];
        }
        
        return blockSize;
        
    }
    
    /**
     * Do the appropriate processing for CFB mode decryption.
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
        
        cipher.processBlock(FR, 0, FRE, 0);
        for (int n = 0; n < blockSize; n++) 
        {
            out[outOff + n] = encryptByte(in[inOff + n], n);
        }
        
        for (int n = 0; n < blockSize; n++) 
        {
            FR[n] = in[inOff + n];
        }
        
        return blockSize;
        
    }
}
