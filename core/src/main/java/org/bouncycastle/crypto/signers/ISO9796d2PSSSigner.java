package org.bouncycastle.crypto.signers;

import java.security.SecureRandom;
import java.util.Hashtable;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithSalt;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/**
 * ISO9796-2 - mechanism using a hash function with recovery (scheme 2 and 3).
 * <p>
 * Note: the usual length for the salt is the length of the hash
 * function used in bytes.
 */
public class ISO9796d2PSSSigner
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

    private static Hashtable trailerMap          = new Hashtable();

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

    private Digest digest;
    private AsymmetricBlockCipher cipher;

    private SecureRandom random;
    private byte[] standardSalt;

    private int hLen;
    private int trailer;
    private int keyBits;
    private byte[] block;
    private byte[] mBuf;
    private int messageLength;
    private int saltLength;
    private boolean fullMessage;
    private byte[] recoveredMessage;

    private byte[] preSig;
    private byte[] preBlock;
    private int preMStart;
    private int preTLength;

    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2, scheme 2 or 3.
     *
     * @param cipher     base cipher to use for signature creation/verification
     * @param digest     digest to use.
     * @param saltLength length of salt in bytes.
     * @param implicit   whether or not the trailer is implicit or gives the hash.
     */
    public ISO9796d2PSSSigner(
        AsymmetricBlockCipher cipher,
        Digest digest,
        int saltLength,
        boolean implicit)
    {
        this.cipher = cipher;
        this.digest = digest;
        this.hLen = digest.getDigestSize();
        this.saltLength = saltLength;

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
     * @param cipher     cipher to use.
     * @param digest     digest to sign with.
     * @param saltLength length of salt in bytes.
     */
    public ISO9796d2PSSSigner(
        AsymmetricBlockCipher cipher,
        Digest digest,
        int saltLength)
    {
        this(cipher, digest, saltLength, false);
    }

    /**
     * Initialise the signer.
     *
     * @param forSigning true if for signing, false if for verification.
     * @param param      parameters for signature generation/verification. If the
     *                   parameters are for generation they should be a ParametersWithRandom,
     *                   a ParametersWithSalt, or just an RSAKeyParameters object. If RSAKeyParameters
     *                   are passed in a SecureRandom will be created.
     * @throws IllegalArgumentException if wrong parameter type or a fixed
     * salt is passed in which is the wrong length.
     */
    public void init(
        boolean forSigning,
        CipherParameters param)
    {
        RSAKeyParameters kParam;
        int lengthOfSalt = saltLength;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom p = (ParametersWithRandom)param;

            kParam = (RSAKeyParameters)p.getParameters();
            if (forSigning)
            {
                random = p.getRandom();
            }
        }
        else if (param instanceof ParametersWithSalt)
        {
            ParametersWithSalt p = (ParametersWithSalt)param;

            kParam = (RSAKeyParameters)p.getParameters();
            standardSalt = p.getSalt();
            lengthOfSalt = standardSalt.length;
            if (standardSalt.length != saltLength)
            {
                throw new IllegalArgumentException("Fixed salt is of wrong length");
            }
        }
        else
        {
            kParam = (RSAKeyParameters)param;
            if (forSigning)
            {
                random = new SecureRandom();
            }
        }

        cipher.init(forSigning, kParam);

        keyBits = kParam.getModulus().bitLength();

        block = new byte[(keyBits + 7) / 8];

        if (trailer == TRAILER_IMPLICIT)
        {
            mBuf = new byte[block.length - digest.getDigestSize() - lengthOfSalt - 1 - 1];
        }
        else
        {
            mBuf = new byte[block.length - digest.getDigestSize() - lengthOfSalt - 1 - 2];
        }

        reset();
    }

    /**
     * compare two byte arrays - constant time
     */
    private boolean isSameAs(
        byte[] a,
        byte[] b)
    {
        boolean isOkay = true;

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

        return isOkay;
    }

    /**
     * clear possible sensitive data
     */
    private void clearBlock(
        byte[] block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    public void updateWithRecoveredMessage(byte[] signature)
        throws InvalidCipherTextException
    {
        byte[] block = cipher.processBlock(signature, 0, signature.length);

        //
        // adjust block size for leading zeroes if necessary
        //
        if (block.length < (keyBits + 7) / 8)
        {
            byte[] tmp = new byte[(keyBits + 7) / 8];

            System.arraycopy(block, 0, tmp, tmp.length - block.length, block.length);
            clearBlock(block);
            block = tmp;
        }

        int tLength;

        if (((block[block.length - 1] & 0xFF) ^ 0xBC) == 0)
        {
            tLength = 1;
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

            tLength = 2;
        }

        //
        // calculate H(m2)
        //
        byte[] m2Hash = new byte[hLen];
        digest.doFinal(m2Hash, 0);

        //
        // remove the mask
        //
        byte[] dbMask = maskGeneratorFunction1(block, block.length - hLen - tLength, hLen, block.length - hLen - tLength);
        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        block[0] &= 0x7f;

        //
        // find out how much padding we've got
        //
        int mStart = 0;
        for (; mStart != block.length; mStart++)
        {
            if (block[mStart] == 0x01)
            {
                break;
            }
        }

        mStart++;

        if (mStart >= block.length)
        {
            clearBlock(block);
        }

        fullMessage = (mStart > 1);

        recoveredMessage = new byte[dbMask.length - mStart - saltLength];

        System.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.length);
        System.arraycopy(recoveredMessage, 0, mBuf, 0, recoveredMessage.length);

        preSig = signature;
        preBlock = block;
        preMStart = mStart;
        preTLength = tLength;
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte b)
    {
        if (preSig == null && messageLength < mBuf.length)
        {
            mBuf[messageLength++] = b;
        }
        else
        {
            digest.update(b);
        }
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[] in,
        int off,
        int len)
    {
        if (preSig == null)
        {
            while (len > 0 && messageLength < mBuf.length)
            {
                this.update(in[off]);
                off++;
                len--;
            }
        }

        if (len > 0)
        {
            digest.update(in, off, len);
        }
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
        messageLength = 0;
        if (mBuf != null)
        {
            clearBlock(mBuf);
        }
        if (recoveredMessage != null)
        {
            clearBlock(recoveredMessage);
            recoveredMessage = null;
        }
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
        int digSize = digest.getDigestSize();

        byte[] m2Hash = new byte[digSize];

        digest.doFinal(m2Hash, 0);

        byte[] C = new byte[8];
        LtoOSP(messageLength * 8, C);

        digest.update(C, 0, C.length);

        digest.update(mBuf, 0, messageLength);

        digest.update(m2Hash, 0, m2Hash.length);

        byte[] salt;

        if (standardSalt != null)
        {
            salt = standardSalt;
        }
        else
        {
            salt = new byte[saltLength];
            random.nextBytes(salt);
        }

        digest.update(salt, 0, salt.length);

        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        int tLength = 2;
        if (trailer == TRAILER_IMPLICIT)
        {
            tLength = 1;
        }

        int off = block.length - messageLength - salt.length - hLen - tLength - 1;

        block[off] = 0x01;

        System.arraycopy(mBuf, 0, block, off + 1, messageLength);
        System.arraycopy(salt, 0, block, off + 1 + messageLength, salt.length);

        byte[] dbMask = maskGeneratorFunction1(hash, 0, hash.length, block.length - hLen - tLength);
        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        System.arraycopy(hash, 0, block, block.length - hLen - tLength, hLen);

        if (trailer == TRAILER_IMPLICIT)
        {
            block[block.length - 1] = (byte)TRAILER_IMPLICIT;
        }
        else
        {
            block[block.length - 2] = (byte)(trailer >>> 8);
            block[block.length - 1] = (byte)trailer;
        }

        block[0] &= 0x7f;

        byte[] b = cipher.processBlock(block, 0, block.length);

        clearBlock(mBuf);
        clearBlock(block);
        messageLength = 0;

        return b;
    }

    /**
     * return true if the signature represents a ISO9796-2 signature
     * for the passed in message.
     */
    public boolean verifySignature(
        byte[] signature)
    {
        //
        // calculate H(m2)
        //
        byte[] m2Hash = new byte[hLen];
        digest.doFinal(m2Hash, 0);

        byte[] block;
        int tLength;
        int mStart = 0;

        if (preSig == null)
        {
            try
            {
                updateWithRecoveredMessage(signature);
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
        }

        block = preBlock;
        mStart = preMStart;
        tLength = preTLength;

        preSig = null;
        preBlock = null;

        //
        // check the hashes
        //
        byte[] C = new byte[8];
        LtoOSP(recoveredMessage.length * 8, C);

        digest.update(C, 0, C.length);

        if (recoveredMessage.length != 0)
        {
            digest.update(recoveredMessage, 0, recoveredMessage.length);
        }

        digest.update(m2Hash, 0, m2Hash.length);

        // Update for the salt
        digest.update(block, mStart + recoveredMessage.length, saltLength);

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        int off = block.length - tLength - hash.length;

        boolean isOkay = true;

        for (int i = 0; i != hash.length; i++)
        {
            if (hash[i] != block[off + i])
            {
                isOkay = false;
            }
        }

        clearBlock(block);
        clearBlock(hash);

        if (!isOkay)
        {
            fullMessage = false;
            clearBlock(recoveredMessage);
            return false;
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
                return false;
            }
            messageLength = 0;
        }

        clearBlock(mBuf);
        return true;
    }

    /**
     * Return true if the full message was recoveredMessage.
     *
     * @return true on full message recovery, false otherwise, or if not sure.
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

    /**
     * int to octet string.
     */
    private void ItoOSP(
        int i,
        byte[] sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }

    /**
     * long to octet string.
     */
    private void LtoOSP(
        long l,
        byte[] sp)
    {
        sp[0] = (byte)(l >>> 56);
        sp[1] = (byte)(l >>> 48);
        sp[2] = (byte)(l >>> 40);
        sp[3] = (byte)(l >>> 32);
        sp[4] = (byte)(l >>> 24);
        sp[5] = (byte)(l >>> 16);
        sp[6] = (byte)(l >>> 8);
        sp[7] = (byte)(l >>> 0);
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private byte[] maskGeneratorFunction1(
        byte[] Z,
        int zOff,
        int zLen,
        int length)
    {
        byte[] mask = new byte[length];
        byte[] hashBuf = new byte[hLen];
        byte[] C = new byte[4];
        int counter = 0;

        digest.reset();

        while (counter < (length / hLen))
        {
            ItoOSP(counter, C);

            digest.update(Z, zOff, zLen);
            digest.update(C, 0, C.length);
            digest.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * hLen, hLen);

            counter++;
        }

        if ((counter * hLen) < length)
        {
            ItoOSP(counter, C);

            digest.update(Z, zOff, zLen);
            digest.update(C, 0, C.length);
            digest.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * hLen, mask.length - (counter * hLen));
        }

        return mask;
    }
}
