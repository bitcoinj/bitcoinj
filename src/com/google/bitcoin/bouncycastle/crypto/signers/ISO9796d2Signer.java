package com.google.bitcoin.bouncycastle.crypto.signers;

import com.google.bitcoin.bouncycastle.crypto.AsymmetricBlockCipher;
import com.google.bitcoin.bouncycastle.crypto.CipherParameters;
import com.google.bitcoin.bouncycastle.crypto.CryptoException;
import com.google.bitcoin.bouncycastle.crypto.Digest;
import com.google.bitcoin.bouncycastle.crypto.SignerWithRecovery;
import com.google.bitcoin.bouncycastle.crypto.digests.RIPEMD128Digest;
import com.google.bitcoin.bouncycastle.crypto.digests.RIPEMD160Digest;
import com.google.bitcoin.bouncycastle.crypto.digests.SHA1Digest;
import com.google.bitcoin.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * ISO9796-2 - mechanism using a hash function with recovery (scheme 1)
 */
public class ISO9796d2Signer
    implements SignerWithRecovery
{
    static final public int   TRAILER_IMPLICIT    = 0xBC;
    static final public int   TRAILER_RIPEMD160   = 0x31CC;
    static final public int   TRAILER_RIPEMD128   = 0x32CC;
    static final public int   TRAILER_SHA1        = 0x33CC;

    private Digest                      digest;
    private AsymmetricBlockCipher       cipher;

    private int         trailer;
    private int         keyBits;
    private byte[]      block;
    private byte[]      mBuf;
    private int         messageLength;
    private boolean     fullMessage;
    private byte[]      recoveredMessage;

    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     * 
     * @param cipher base cipher to use for signature creation/verification
     * @param digest digest to use.
     * @param implicit whether or not the trailer is implicit or gives the hash.
     */
    public ISO9796d2Signer(
        AsymmetricBlockCipher   cipher,
        Digest                  digest,
        boolean                 implicit)
    {
        this.cipher = cipher;
        this.digest = digest;

        if (implicit)
        {
            trailer = TRAILER_IMPLICIT;
        }
        else
        {
            if (digest instanceof SHA1Digest)
            {
                trailer = TRAILER_SHA1;
            }
            else if (digest instanceof RIPEMD160Digest)
            {
                trailer = TRAILER_RIPEMD160;
            }
            else if (digest instanceof RIPEMD128Digest)
            {
                trailer = TRAILER_RIPEMD128;
            }
            else
            {
                throw new IllegalArgumentException("no valid trailer for digest");
            }
        }
    }

    /**
     * Constructor for a signer with an explicit digest trailer.
     * 
     * @param cipher cipher to use.
     * @param digest digest to sign with.
     */
    public ISO9796d2Signer(
        AsymmetricBlockCipher   cipher,
        Digest                  digest)
    {
        this(cipher, digest, false);
    }
    
    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        RSAKeyParameters  kParam = (RSAKeyParameters)param;

        cipher.init(forSigning, kParam);

        keyBits = kParam.getModulus().bitLength();

        block = new byte[(keyBits + 7) / 8];
        
        if (trailer == TRAILER_IMPLICIT)
        {
            mBuf = new byte[block.length - digest.getDigestSize() - 2];
        }
        else
        {
            mBuf = new byte[block.length - digest.getDigestSize() - 3];
        }

        reset();
    }

    /**
     * compare two byte arrays.
     */
    private boolean isSameAs(
        byte[]    a,
        byte[]    b)
    {
        if (messageLength > mBuf.length)
        {
            if (mBuf.length > b.length)
            {
                return false;
            }
            
            for (int i = 0; i != mBuf.length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
        }
        else
        {
            if (messageLength != b.length)
            {
                return false;
            }
            
            for (int i = 0; i != b.length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    /**
     * clear possible sensitive data
     */
    private void clearBlock(
        byte[]  block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte    b)
    {
        digest.update(b);

        if (messageLength < mBuf.length)
        {
            mBuf[messageLength] = b;
        }

        messageLength++;
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  in,
        int     off,
        int     len)
    {
        digest.update(in, off, len);

        if (messageLength < mBuf.length)
        {
            for (int i = 0; i < len && (i + messageLength) < mBuf.length; i++)
            {
                mBuf[messageLength + i] = in[off + i];
            }
        }

        messageLength += len;
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
        messageLength = 0;
        clearBlock(mBuf);
        
        if (recoveredMessage != null)
        {
            clearBlock(recoveredMessage);
        }
        
        recoveredMessage = null;
        fullMessage = false;
    }

    /**
     * generate a signature for the loaded message using the key we were
     * initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException
    {
        int     digSize = digest.getDigestSize();

        int t = 0;
        int delta = 0;

        if (trailer == TRAILER_IMPLICIT)
        {
            t = 8;
            delta = block.length - digSize - 1;
            digest.doFinal(block, delta);
            block[block.length - 1] = (byte)TRAILER_IMPLICIT;
        }
        else
        {
            t = 16;
            delta = block.length - digSize - 2;
            digest.doFinal(block, delta);
            block[block.length - 2] = (byte)(trailer >>> 8);
            block[block.length - 1] = (byte)trailer;
        }

        byte    header = 0;
        int     x = (digSize + messageLength) * 8 + t + 4 - keyBits;

        if (x > 0)
        {
            int mR = messageLength - ((x + 7) / 8);
            header = 0x60;

            delta -= mR;
            
            System.arraycopy(mBuf, 0, block, delta, mR);
        }
        else
        {
            header = 0x40;
            delta -= messageLength;
            
            System.arraycopy(mBuf, 0, block, delta, messageLength);
        }
        
        if ((delta - 1) > 0)
        {
            for (int i = delta - 1; i != 0; i--)
            {
                block[i] = (byte)0xbb;
            }
            block[delta - 1] ^= (byte)0x01;
            block[0] = (byte)0x0b;
            block[0] |= header;
        }
        else
        {
            block[0] = (byte)0x0a;
            block[0] |= header;
        }

        byte[]  b = cipher.processBlock(block, 0, block.length);

        clearBlock(mBuf);
        clearBlock(block);

        return b;
    }

    /**
     * return true if the signature represents a ISO9796-2 signature
     * for the passed in message.
     */
    public boolean verifySignature(
        byte[]      signature)
    {
        byte[]      block = null;

        try
        {
            block = cipher.processBlock(signature, 0, signature.length);
        }
        catch (Exception e)
        {
            return false;
        }

        if (((block[0] & 0xC0) ^ 0x40) != 0)
        {
            clearBlock(mBuf);
            clearBlock(block);

            return false;
        }

        if (((block[block.length - 1] & 0xF) ^ 0xC) != 0)
        {
            clearBlock(mBuf);
            clearBlock(block);

            return false;
        }

        int     delta = 0;

        if (((block[block.length - 1] & 0xFF) ^ 0xBC) == 0)
        {
            delta = 1;
        }
        else
        {
            int sigTrail = ((block[block.length - 2] & 0xFF) << 8) | (block[block.length - 1] & 0xFF);

            switch (sigTrail)
            {
            case TRAILER_RIPEMD160:
                    if (!(digest instanceof RIPEMD160Digest))
                    {
                        throw new IllegalStateException("signer should be initialised with RIPEMD160");
                    }
                    break;
            case TRAILER_SHA1:
                    if (!(digest instanceof SHA1Digest))
                    {
                        throw new IllegalStateException("signer should be initialised with SHA1");
                    }
                    break;
            case TRAILER_RIPEMD128:
                    if (!(digest instanceof RIPEMD128Digest))
                    {
                        throw new IllegalStateException("signer should be initialised with RIPEMD128");
                    }
                    break;
            default:
                throw new IllegalArgumentException("unrecognised hash in signature");
            }

            delta = 2;
        }

        //
        // find out how much padding we've got
        //
        int mStart = 0;

        for (mStart = 0; mStart != block.length; mStart++)
        {
            if (((block[mStart] & 0x0f) ^ 0x0a) == 0)
            {
                break;
            }
        }

        mStart++;

        //
        // check the hashes
        //
        byte[]  hash = new byte[digest.getDigestSize()];

        int off = block.length - delta - hash.length;

        //
        // there must be at least one byte of message string
        //
        if ((off - mStart) <= 0)
        {
            clearBlock(mBuf);
            clearBlock(block);

            return false;
        }

        //
        // if we contain the whole message as well, check the hash of that.
        //
        if ((block[0] & 0x20) == 0)
        {
            fullMessage = true;
            
            digest.reset();
            digest.update(block, mStart, off - mStart);
            digest.doFinal(hash, 0);
            
            for (int i = 0; i != hash.length; i++)
            {
                block[off + i] ^= hash[i];
                if (block[off + i] != 0)
                {
                    clearBlock(mBuf);
                    clearBlock(block);

                    return false;
                }
            }
            
            recoveredMessage = new byte[off - mStart];
            System.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.length);
        }
        else
        {
            fullMessage = false;
            
            digest.doFinal(hash, 0);
            
            for (int i = 0; i != hash.length; i++)
            {
                block[off + i] ^= hash[i];
                if (block[off + i] != 0)
                {
                    clearBlock(mBuf);
                    clearBlock(block);

                    return false;
                }
            }
            
            recoveredMessage = new byte[off - mStart];
            System.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.length);
        }

        //
        // if they've input a message check what we've recovered against
        // what was input.
        //
        if (messageLength != 0)
        {
            if (!isSameAs(mBuf, recoveredMessage))
            {
                clearBlock(mBuf);
                clearBlock(block);

                return false;
            }
        }
        
        clearBlock(mBuf);
        clearBlock(block);

        return true;
    }

    /**
     * Return true if the full message was recoveredMessage.
     * 
     * @return true on full message recovery, false otherwise.
     * @see com.google.bitcoin.bouncycastle.crypto.SignerWithRecovery#hasFullMessage()
     */
    public boolean hasFullMessage()
    {
        return fullMessage;
    }

    /**
     * Return a reference to the recoveredMessage message.
     * 
     * @return the full/partial recoveredMessage message.
     * @see com.google.bitcoin.bouncycastle.crypto.SignerWithRecovery#getRecoveredMessage()
     */
    public byte[] getRecoveredMessage()
    {
        return recoveredMessage;
    }
}
