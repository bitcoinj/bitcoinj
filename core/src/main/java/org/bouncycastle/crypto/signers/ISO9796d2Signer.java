package org.bouncycastle.crypto.signers;

import java.util.Hashtable;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

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
    static final public int   TRAILER_SHA256      = 0x34CC;
    static final public int   TRAILER_SHA512      = 0x35CC;
    static final public int   TRAILER_SHA384      = 0x36CC;
    static final public int   TRAILER_WHIRLPOOL   = 0x37CC;

    private static Hashtable  trailerMap          = new Hashtable();

    static
    {
        trailerMap.put("RIPEMD128", Integers.valueOf(TRAILER_RIPEMD128));
        trailerMap.put("RIPEMD160", Integers.valueOf(TRAILER_RIPEMD160));

        trailerMap.put("SHA-1", Integers.valueOf(TRAILER_SHA1));
        trailerMap.put("SHA-256", Integers.valueOf(TRAILER_SHA256));
        trailerMap.put("SHA-384", Integers.valueOf(TRAILER_SHA384));
        trailerMap.put("SHA-512", Integers.valueOf(TRAILER_SHA512));

        trailerMap.put("Whirlpool", Integers.valueOf(TRAILER_WHIRLPOOL));
    }

    private Digest                      digest;
    private AsymmetricBlockCipher       cipher;

    private int         trailer;
    private int         keyBits;
    private byte[]      block;
    private byte[]      mBuf;
    private int         messageLength;
    private boolean     fullMessage;
    private byte[]      recoveredMessage;

    private byte[]      preSig;
    private byte[]      preBlock;

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
            Integer trailerObj = (Integer)trailerMap.get(digest.getAlgorithmName());

            if (trailerObj != null)
            {
                trailer = trailerObj.intValue();
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
     * compare two byte arrays - constant time
     */
    private boolean isSameAs(
        byte[]    a,
        byte[]    b)
    {
        boolean isOkay = true;

        if (messageLength > mBuf.length)
        {
            if (mBuf.length > b.length)
            {
                isOkay = false;
            }
            
            for (int i = 0; i != mBuf.length; i++)
            {
                if (a[i] != b[i])
                {
                    isOkay = false;
                }
            }
        }
        else
        {
            if (messageLength != b.length)
            {
                isOkay = false;
            }
            
            for (int i = 0; i != b.length; i++)
            {
                if (a[i] != b[i])
                {
                    isOkay = false;
                }
            }
        }
        
        return isOkay;
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

    public void updateWithRecoveredMessage(byte[] signature)
        throws InvalidCipherTextException
    {
        byte[]      block = cipher.processBlock(signature, 0, signature.length);

        if (((block[0] & 0xC0) ^ 0x40) != 0)
        {
            throw new InvalidCipherTextException("malformed signature");
        }

        if (((block[block.length - 1] & 0xF) ^ 0xC) != 0)
        {
            throw new InvalidCipherTextException("malformed signature");
        }

        int     delta = 0;

        if (((block[block.length - 1] & 0xFF) ^ 0xBC) == 0)
        {
            delta = 1;
        }
        else
        {
            int sigTrail = ((block[block.length - 2] & 0xFF) << 8) | (block[block.length - 1] & 0xFF);
            Integer trailerObj = (Integer)trailerMap.get(digest.getAlgorithmName());

            if (trailerObj != null)
            {
                if (sigTrail != trailerObj.intValue())
                {
                    throw new IllegalStateException("signer initialised with wrong digest for trailer " + sigTrail);
                }
            }
            else
            {
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

        int off = block.length - delta - digest.getDigestSize();

        //
        // there must be at least one byte of message string
        //
        if ((off - mStart) <= 0)
        {
            throw new InvalidCipherTextException("malformed block");
        }

        //
        // if we contain the whole message as well, check the hash of that.
        //
        if ((block[0] & 0x20) == 0)
        {
            fullMessage = true;

            recoveredMessage = new byte[off - mStart];
            System.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.length);
        }
        else
        {
            fullMessage = false;

            recoveredMessage = new byte[off - mStart];
            System.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.length);
        }

        preSig = signature;
        preBlock = block;

        digest.update(recoveredMessage, 0, recoveredMessage.length);
        messageLength = recoveredMessage.length;
        System.arraycopy(recoveredMessage, 0, mBuf, 0, recoveredMessage.length);
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
        while (len > 0 && messageLength < mBuf.length)
        {
            this.update(in[off]);
            off++;
            len--;
        }

        digest.update(in, off, len);
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

        if (preSig != null)
        {
            preSig = null;
            clearBlock(preBlock);
            preBlock = null;
        }
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

        if (preSig == null)
        {
            try
            {
                block = cipher.processBlock(signature, 0, signature.length);
            }
            catch (Exception e)
            {
                return false;
            }
        }
        else
        {
            if (!Arrays.areEqual(preSig, signature))
            {
                throw new IllegalStateException("updateWithRecoveredMessage called on different signature");
            }

            block = preBlock;

            preSig = null;
            preBlock = null;
        }

        if (((block[0] & 0xC0) ^ 0x40) != 0)
        {
            return returnFalse(block);
        }

        if (((block[block.length - 1] & 0xF) ^ 0xC) != 0)
        {
            return returnFalse(block);
        }

        int     delta = 0;

        if (((block[block.length - 1] & 0xFF) ^ 0xBC) == 0)
        {
            delta = 1;
        }
        else
        {
            int sigTrail = ((block[block.length - 2] & 0xFF) << 8) | (block[block.length - 1] & 0xFF);
            Integer trailerObj = (Integer)trailerMap.get(digest.getAlgorithmName());

            if (trailerObj != null)
            {
                if (sigTrail != trailerObj.intValue())
                {
                    throw new IllegalStateException("signer initialised with wrong digest for trailer " + sigTrail);
                }
            }
            else
            {
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
            return returnFalse(block);
        }

        //
        // if we contain the whole message as well, check the hash of that.
        //
        if ((block[0] & 0x20) == 0)
        {
            fullMessage = true;

            // check right number of bytes passed in.
            if (messageLength > off - mStart)
            {
                return returnFalse(block);
            }
            
            digest.reset();
            digest.update(block, mStart, off - mStart);
            digest.doFinal(hash, 0);

            boolean isOkay = true;

            for (int i = 0; i != hash.length; i++)
            {
                block[off + i] ^= hash[i];
                if (block[off + i] != 0)
                {
                    isOkay = false;
                }
            }

            if (!isOkay)
            {
                return returnFalse(block);
            }

            recoveredMessage = new byte[off - mStart];
            System.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.length);
        }
        else
        {
            fullMessage = false;
            
            digest.doFinal(hash, 0);

            boolean isOkay = true;

            for (int i = 0; i != hash.length; i++)
            {
                block[off + i] ^= hash[i];
                if (block[off + i] != 0)
                {
                    isOkay = false;
                }
            }

            if (!isOkay)
            {
                return returnFalse(block);
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
                return returnFalse(block);
            }
        }
        
        clearBlock(mBuf);
        clearBlock(block);

        return true;
    }

    private boolean returnFalse(byte[] block)
    {
        clearBlock(mBuf);
        clearBlock(block);

        return false;
    }

    /**
     * Return true if the full message was recoveredMessage.
     * 
     * @return true on full message recovery, false otherwise.
     * @see org.bouncycastle.crypto.SignerWithRecovery#hasFullMessage()
     */
    public boolean hasFullMessage()
    {
        return fullMessage;
    }

    /**
     * Return a reference to the recoveredMessage message.
     * 
     * @return the full/partial recoveredMessage message.
     * @see org.bouncycastle.crypto.SignerWithRecovery#getRecoveredMessage()
     */
    public byte[] getRecoveredMessage()
    {
        return recoveredMessage;
    }
}
