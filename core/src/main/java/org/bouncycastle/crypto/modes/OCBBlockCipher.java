package org.bouncycastle.crypto.modes;

import java.util.Vector;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * An implementation of the "work in progress" Internet-Draft <a
 * href="http://tools.ietf.org/html/draft-irtf-cfrg-ocb-07">The OCB Authenticated-Encryption
 * Algorithm</a>, licensed per:
 * <p>
 * <blockquote> <a href="http://www.cs.ucdavis.edu/~rogaway/ocb/license1.pdf">License for
 * Open-Source Software Implementations of OCB</a> (Jan 9, 2013) &mdash; &ldquo;License 1&rdquo; <br>
 * Under this license, you are authorized to make, use, and distribute open-source software
 * implementations of OCB. This license terminates for you if you sue someone over their open-source
 * software implementation of OCB claiming that you have a patent covering their implementation.
 * <p>
 * This is a non-binding summary of a legal document (the link above). The parameters of the license
 * are specified in the license document and that document is controlling. </blockquote>
 */
public class OCBBlockCipher
    implements AEADBlockCipher
{
    private static final int BLOCK_SIZE = 16;

    private BlockCipher hashCipher;
    private BlockCipher mainCipher;

    /*
     * CONFIGURATION
     */
    private boolean forEncryption;
    private int macSize;
    private byte[] initialAssociatedText;

    /*
     * KEY-DEPENDENT
     */
    // NOTE: elements are lazily calculated
    private Vector L;
    private byte[] L_Asterisk, L_Dollar;

    /*
     * NONCE-DEPENDENT
     */
    private byte[] KtopInput = null;
    private byte[] Stretch = new byte[24];
    private byte[] OffsetMAIN_0 = new byte[16];

    /*
     * PER-ENCRYPTION/DECRYPTION
     */
    private byte[] hashBlock, mainBlock;
    private int hashBlockPos, mainBlockPos;
    private long hashBlockCount, mainBlockCount;
    private byte[] OffsetHASH;
    private byte[] Sum;
    private byte[] OffsetMAIN = new byte[16];
    private byte[] Checksum;

    // NOTE: The MAC value is preserved after doFinal
    private byte[] macBlock;

    public OCBBlockCipher(BlockCipher hashCipher, BlockCipher mainCipher)
    {
        if (hashCipher == null)
        {
            throw new IllegalArgumentException("'hashCipher' cannot be null");
        }
        if (hashCipher.getBlockSize() != BLOCK_SIZE)
        {
            throw new IllegalArgumentException("'hashCipher' must have a block size of "
                + BLOCK_SIZE);
        }
        if (mainCipher == null)
        {
            throw new IllegalArgumentException("'mainCipher' cannot be null");
        }
        if (mainCipher.getBlockSize() != BLOCK_SIZE)
        {
            throw new IllegalArgumentException("'mainCipher' must have a block size of "
                + BLOCK_SIZE);
        }

        if (!hashCipher.getAlgorithmName().equals(mainCipher.getAlgorithmName()))
        {
            throw new IllegalArgumentException(
                "'hashCipher' and 'mainCipher' must be the same algorithm");
        }

        this.hashCipher = hashCipher;
        this.mainCipher = mainCipher;
    }

    public BlockCipher getUnderlyingCipher()
    {
        return mainCipher;
    }

    public String getAlgorithmName()
    {
        return mainCipher.getAlgorithmName() + "/OCB";
    }

    public void init(boolean forEncryption, CipherParameters parameters)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        this.macBlock = null;

        KeyParameter keyParameter;

        byte[] N;
        if (parameters instanceof AEADParameters)
        {
            AEADParameters aeadParameters = (AEADParameters)parameters;

            N = aeadParameters.getNonce();
            initialAssociatedText = aeadParameters.getAssociatedText();

            int macSizeBits = aeadParameters.getMacSize();
            if (macSizeBits < 64 || macSizeBits > 128 || macSizeBits % 8 != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            macSize = macSizeBits / 8;
            keyParameter = aeadParameters.getKey();
        }
        else if (parameters instanceof ParametersWithIV)
        {
            ParametersWithIV parametersWithIV = (ParametersWithIV)parameters;

            N = parametersWithIV.getIV();
            initialAssociatedText = null;
            macSize = 16;
            keyParameter = (KeyParameter)parametersWithIV.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to OCB");
        }

        this.hashBlock = new byte[16];
        this.mainBlock = new byte[forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize)];

        if (N == null)
        {
            N = new byte[0];
        }

        if (N.length > 15)
        {
            throw new IllegalArgumentException("IV must be no more than 15 bytes");
        }

        /*
         * KEY-DEPENDENT INITIALISATION
         */

        if (keyParameter == null)
        {
            // TODO If 'keyParameter' is null we're re-using the last key.
        }
        else
        {
            KtopInput = null;
        }

        // hashCipher always used in forward mode
        hashCipher.init(true, keyParameter);
        mainCipher.init(forEncryption, keyParameter);

        this.L_Asterisk = new byte[16];
        hashCipher.processBlock(L_Asterisk, 0, L_Asterisk, 0);

        this.L_Dollar = OCB_double(L_Asterisk);

        this.L = new Vector();
        this.L.addElement(OCB_double(L_Dollar));

        /*
         * NONCE-DEPENDENT AND PER-ENCRYPTION/DECRYPTION INITIALISATION
         */

        int bottom = processNonce(N);

        int bits = bottom % 8, bytes = bottom / 8;
        if (bits == 0)
        {
            System.arraycopy(Stretch, bytes, OffsetMAIN_0, 0, 16);
        }
        else
        {
            for (int i = 0; i < 16; ++i)
            {
                int b1 = Stretch[bytes] & 0xff;
                int b2 = Stretch[++bytes] & 0xff;
                this.OffsetMAIN_0[i] = (byte)((b1 << bits) | (b2 >>> (8 - bits)));
            }
        }

        this.hashBlockPos = 0;
        this.mainBlockPos = 0;

        this.hashBlockCount = 0;
        this.mainBlockCount = 0;

        this.OffsetHASH = new byte[16];
        this.Sum = new byte[16];
        System.arraycopy(this.OffsetMAIN_0, 0, this.OffsetMAIN, 0, 16);
        this.Checksum = new byte[16];

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    protected int processNonce(byte[] N)
    {
        byte[] nonce = new byte[16];
        System.arraycopy(N, 0, nonce, nonce.length - N.length, N.length);
        nonce[0] = (byte)(macSize << 4);
        nonce[15 - N.length] |= 1;

        int bottom = nonce[15] & 0x3F;
        nonce[15] &= 0xC0;

        /*
         * When used with incrementing nonces, the cipher is only applied once every 64 inits.
         */
        if (KtopInput == null || !Arrays.areEqual(nonce, KtopInput))
        {
            byte[] Ktop = new byte[16];
            KtopInput = nonce;
            hashCipher.processBlock(KtopInput, 0, Ktop, 0);
            System.arraycopy(Ktop, 0, Stretch, 0, 16);
            for (int i = 0; i < 8; ++i)
            {
                Stretch[16 + i] = (byte)(Ktop[i] ^ Ktop[i + 1]);
            }
        }

        return bottom;
    }

    public byte[] getMac()
    {
        return Arrays.clone(macBlock);
    }

    public int getOutputSize(int len)
    {
        int totalData = len + mainBlockPos;
        if (forEncryption)
        {
            return totalData + macSize;
        }
        return totalData < macSize ? 0 : totalData - macSize;
    }

    public int getUpdateOutputSize(int len)
    {
        int totalData = len + mainBlockPos;
        if (!forEncryption)
        {
            if (totalData < macSize)
            {
                return 0;
            }
            totalData -= macSize;
        }
        return totalData - totalData % BLOCK_SIZE;
    }

    public void processAADByte(byte input)
    {
        hashBlock[hashBlockPos] = input;
        if (++hashBlockPos == hashBlock.length)
        {
            processHashBlock();
        }
    }

    public void processAADBytes(byte[] input, int off, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            hashBlock[hashBlockPos] = input[off + i];
            if (++hashBlockPos == hashBlock.length)
            {
                processHashBlock();
            }
        }
    }

    public int processByte(byte input, byte[] output, int outOff)
        throws DataLengthException
    {
        mainBlock[mainBlockPos] = input;
        if (++mainBlockPos == mainBlock.length)
        {
            processMainBlock(output, outOff);
            return BLOCK_SIZE;
        }
        return 0;
    }

    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (input.length < (inOff + len))
        {
            throw new DataLengthException("Input buffer too short");
        }
        int resultLen = 0;

        for (int i = 0; i < len; ++i)
        {
            mainBlock[mainBlockPos] = input[inOff + i];
            if (++mainBlockPos == mainBlock.length)
            {
                processMainBlock(output, outOff + resultLen);
                resultLen += BLOCK_SIZE;
            }
        }

        return resultLen;
    }

    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException,
        InvalidCipherTextException
    {
        /*
         * For decryption, get the tag from the end of the message
         */
        byte[] tag = null;
        if (!forEncryption)
        {
            if (mainBlockPos < macSize)
            {
                throw new InvalidCipherTextException("data too short");
            }
            mainBlockPos -= macSize;
            tag = new byte[macSize];
            System.arraycopy(mainBlock, mainBlockPos, tag, 0, macSize);
        }

        /*
         * HASH: Process any final partial block; compute final hash value
         */
        if (hashBlockPos > 0)
        {
            OCB_extend(hashBlock, hashBlockPos);
            updateHASH(L_Asterisk);
        }

        /*
         * OCB-ENCRYPT/OCB-DECRYPT: Process any final partial block
         */
        if (mainBlockPos > 0)
        {
            if (forEncryption)
            {
                OCB_extend(mainBlock, mainBlockPos);
                xor(Checksum, mainBlock);
            }

            xor(OffsetMAIN, L_Asterisk);

            byte[] Pad = new byte[16];
            hashCipher.processBlock(OffsetMAIN, 0, Pad, 0);

            xor(mainBlock, Pad);

            if (output.length < (outOff + mainBlockPos))
            {
                throw new OutputLengthException("Output buffer too short");
            }
            System.arraycopy(mainBlock, 0, output, outOff, mainBlockPos);

            if (!forEncryption)
            {
                OCB_extend(mainBlock, mainBlockPos);
                xor(Checksum, mainBlock);
            }
        }

        /*
         * OCB-ENCRYPT/OCB-DECRYPT: Compute raw tag
         */
        xor(Checksum, OffsetMAIN);
        xor(Checksum, L_Dollar);
        hashCipher.processBlock(Checksum, 0, Checksum, 0);
        xor(Checksum, Sum);

        this.macBlock = new byte[macSize];
        System.arraycopy(Checksum, 0, macBlock, 0, macSize);

        /*
         * Validate or append tag and reset this cipher for the next run
         */
        int resultLen = mainBlockPos;

        if (forEncryption)
        {
            if (output.length < (outOff + resultLen + macSize))
            {
                throw new OutputLengthException("Output buffer too short");
            }
            // Append tag to the message
            System.arraycopy(macBlock, 0, output, outOff + resultLen, macSize);
            resultLen += macSize;
        }
        else
        {
            // Compare the tag from the message with the calculated one
            if (!Arrays.constantTimeAreEqual(macBlock, tag))
            {
                throw new InvalidCipherTextException("mac check in OCB failed");
            }
        }

        reset(false);

        return resultLen;
    }

    public void reset()
    {
        reset(true);
    }

    protected void clear(byte[] bs)
    {
        if (bs != null)
        {
            Arrays.fill(bs, (byte)0);
        }
    }

    protected byte[] getLSub(int n)
    {
        while (n >= L.size())
        {
            L.addElement(OCB_double((byte[])L.lastElement()));
        }
        return (byte[])L.elementAt(n);
    }

    protected void processHashBlock()
    {
        /*
         * HASH: Process any whole blocks
         */
        updateHASH(getLSub(OCB_ntz(++hashBlockCount)));
        hashBlockPos = 0;
    }

    protected void processMainBlock(byte[] output, int outOff)
    {
        if (output.length < (outOff + BLOCK_SIZE))
        {
            throw new OutputLengthException("Output buffer too short");
        }

        /*
         * OCB-ENCRYPT/OCB-DECRYPT: Process any whole blocks
         */

        if (forEncryption)
        {
            xor(Checksum, mainBlock);
            mainBlockPos = 0;
        }

        xor(OffsetMAIN, getLSub(OCB_ntz(++mainBlockCount)));

        xor(mainBlock, OffsetMAIN);
        mainCipher.processBlock(mainBlock, 0, mainBlock, 0);
        xor(mainBlock, OffsetMAIN);

        System.arraycopy(mainBlock, 0, output, outOff, 16);

        if (!forEncryption)
        {
            xor(Checksum, mainBlock);
            System.arraycopy(mainBlock, BLOCK_SIZE, mainBlock, 0, macSize);
            mainBlockPos = macSize;
        }
    }

    protected void reset(boolean clearMac)
    {
        hashCipher.reset();
        mainCipher.reset();

        clear(hashBlock);
        clear(mainBlock);

        hashBlockPos = 0;
        mainBlockPos = 0;

        hashBlockCount = 0;
        mainBlockCount = 0;

        clear(OffsetHASH);
        clear(Sum);
        System.arraycopy(OffsetMAIN_0, 0, OffsetMAIN, 0, 16);
        clear(Checksum);

        if (clearMac)
        {
            macBlock = null;
        }

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    protected void updateHASH(byte[] LSub)
    {
        xor(OffsetHASH, LSub);
        xor(hashBlock, OffsetHASH);
        hashCipher.processBlock(hashBlock, 0, hashBlock, 0);
        xor(Sum, hashBlock);
    }

    protected static byte[] OCB_double(byte[] block)
    {
        byte[] result = new byte[16];
        int carry = shiftLeft(block, result);

        /*
         * NOTE: This construction is an attempt at a constant-time implementation.
         */
        result[15] ^= (0x87 >>> ((1 - carry) << 3));

        return result;
    }

    protected static void OCB_extend(byte[] block, int pos)
    {
        block[pos] = (byte)0x80;
        while (++pos < 16)
        {
            block[pos] = 0;
        }
    }

    protected static int OCB_ntz(long x)
    {
        if (x == 0)
        {
            return 64;
        }

        int n = 0;
        while ((x & 1L) == 0L)
        {
            ++n;
            x >>= 1;
        }
        return n;
    }

    protected static int shiftLeft(byte[] block, byte[] output)
    {
        int i = 16;
        int bit = 0;
        while (--i >= 0)
        {
            int b = block[i] & 0xff;
            output[i] = (byte)((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
        return bit;
    }

    protected static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }
}
