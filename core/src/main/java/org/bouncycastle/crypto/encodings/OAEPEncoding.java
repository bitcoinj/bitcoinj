package org.bouncycastle.crypto.encodings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/**
 * Optimal Asymmetric Encryption Padding (OAEP) - see PKCS 1 V 2.
 */
public class OAEPEncoding
    implements AsymmetricBlockCipher
{
    private byte[]                  defHash;
    private Digest                  mgf1Hash;

    private AsymmetricBlockCipher   engine;
    private SecureRandom            random;
    private boolean                 forEncryption;

    public OAEPEncoding(
        AsymmetricBlockCipher   cipher)
    {
        this(cipher, new SHA1Digest(), null);
    }
    
    public OAEPEncoding(
        AsymmetricBlockCipher       cipher,
        Digest                      hash)
    {
        this(cipher, hash, null);
    }
    
    public OAEPEncoding(
        AsymmetricBlockCipher       cipher,
        Digest                      hash,
        byte[]                      encodingParams)
    {
        this(cipher, hash, hash, encodingParams);
    }

    public OAEPEncoding(
        AsymmetricBlockCipher       cipher,
        Digest                      hash,
        Digest                      mgf1Hash,
        byte[]                      encodingParams)
    {
        this.engine = cipher;
        this.mgf1Hash = mgf1Hash;
        this.defHash = new byte[hash.getDigestSize()];

        hash.reset();

        if (encodingParams != null)
        {
            hash.update(encodingParams, 0, encodingParams.length);
        }

        hash.doFinal(defHash, 0);
    }

    public AsymmetricBlockCipher getUnderlyingCipher()
    {
        return engine;
    }

    public void init(
        boolean             forEncryption,
        CipherParameters    param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom  rParam = (ParametersWithRandom)param;

            this.random = rParam.getRandom();
        }
        else
        {   
            this.random = new SecureRandom();
        }

        engine.init(forEncryption, param);

        this.forEncryption = forEncryption;
    }

    public int getInputBlockSize()
    {
        int     baseBlockSize = engine.getInputBlockSize();

        if (forEncryption)
        {
            return baseBlockSize - 1 - 2 * defHash.length;
        }
        else
        {
            return baseBlockSize;
        }
    }

    public int getOutputBlockSize()
    {
        int     baseBlockSize = engine.getOutputBlockSize();

        if (forEncryption)
        {
            return baseBlockSize;
        }
        else
        {
            return baseBlockSize - 1 - 2 * defHash.length;
        }
    }

    public byte[] processBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        if (forEncryption)
        {
            return encodeBlock(in, inOff, inLen);
        }
        else
        {
            return decodeBlock(in, inOff, inLen);
        }
    }

    public byte[] encodeBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        byte[]  block = new byte[getInputBlockSize() + 1 + 2 * defHash.length];

        //
        // copy in the message
        //
        System.arraycopy(in, inOff, block, block.length - inLen, inLen);

        //
        // add sentinel
        //
        block[block.length - inLen - 1] = 0x01;

        //
        // as the block is already zeroed - there's no need to add PS (the >= 0 pad of 0)
        //

        //
        // add the hash of the encoding params.
        //
        System.arraycopy(defHash, 0, block, defHash.length, defHash.length);

        //
        // generate the seed.
        //
        byte[]  seed = new byte[defHash.length];

        random.nextBytes(seed);

        //
        // mask the message block.
        //
        byte[]  mask = maskGeneratorFunction1(seed, 0, seed.length, block.length - defHash.length);

        for (int i = defHash.length; i != block.length; i++)
        {
            block[i] ^= mask[i - defHash.length];
        }

        //
        // add in the seed
        //
        System.arraycopy(seed, 0, block, 0, defHash.length);

        //
        // mask the seed.
        //
        mask = maskGeneratorFunction1(
                        block, defHash.length, block.length - defHash.length, defHash.length);

        for (int i = 0; i != defHash.length; i++)
        {
            block[i] ^= mask[i];
        }

        return engine.processBlock(block, 0, block.length);
    }

    /**
     * @exception InvalidCipherTextException if the decrypted block turns out to
     * be badly formatted.
     */
    public byte[] decodeBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        byte[]  data = engine.processBlock(in, inOff, inLen);
        byte[]  block;

        //
        // as we may have zeros in our leading bytes for the block we produced
        // on encryption, we need to make sure our decrypted block comes back
        // the same size.
        //
        if (data.length < engine.getOutputBlockSize())
        {
            block = new byte[engine.getOutputBlockSize()];

            System.arraycopy(data, 0, block, block.length - data.length, data.length);
        }
        else
        {
            block = data;
        }

        if (block.length < (2 * defHash.length) + 1)
        {
            throw new InvalidCipherTextException("data too short");
        }

        //
        // unmask the seed.
        //
        byte[] mask = maskGeneratorFunction1(
                    block, defHash.length, block.length - defHash.length, defHash.length);

        for (int i = 0; i != defHash.length; i++)
        {
            block[i] ^= mask[i];
        }

        //
        // unmask the message block.
        //
        mask = maskGeneratorFunction1(block, 0, defHash.length, block.length - defHash.length);

        for (int i = defHash.length; i != block.length; i++)
        {
            block[i] ^= mask[i - defHash.length];
        }

        //
        // check the hash of the encoding params.
        // long check to try to avoid this been a source of a timing attack.
        //
        boolean defHashWrong = false;

        for (int i = 0; i != defHash.length; i++)
        {
            if (defHash[i] != block[defHash.length + i])
            {
                defHashWrong = true;
            }
        }

        if (defHashWrong)
        {
            throw new InvalidCipherTextException("data hash wrong");
        }

        //
        // find the data block
        //
        int start;

        for (start = 2 * defHash.length; start != block.length; start++)
        {
            if (block[start] != 0)
            {
                break;
            }
        }

        if (start >= (block.length - 1) || block[start] != 1)
        {
            throw new InvalidCipherTextException("data start wrong " + start);
        }

        start++;

        //
        // extract the data block
        //
        byte[]  output = new byte[block.length - start];

        System.arraycopy(block, start, output, 0, output.length);

        return output;
    }

    /**
     * int to octet string.
     */
    private void ItoOSP(
        int     i,
        byte[]  sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private byte[] maskGeneratorFunction1(
        byte[]  Z,
        int     zOff,
        int     zLen,
        int     length)
    {
        byte[]  mask = new byte[length];
        byte[]  hashBuf = new byte[mgf1Hash.getDigestSize()];
        byte[]  C = new byte[4];
        int     counter = 0;

        mgf1Hash.reset();

        while (counter < (length / hashBuf.length))
        {
            ItoOSP(counter, C);

            mgf1Hash.update(Z, zOff, zLen);
            mgf1Hash.update(C, 0, C.length);
            mgf1Hash.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * hashBuf.length, hashBuf.length);

            counter++;
        }

        if ((counter * hashBuf.length) < length)
        {
            ItoOSP(counter, C);

            mgf1Hash.update(Z, zOff, zLen);
            mgf1Hash.update(C, 0, C.length);
            mgf1Hash.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * hashBuf.length, mask.length - (counter * hashBuf.length));
        }

        return mask;
    }
}
