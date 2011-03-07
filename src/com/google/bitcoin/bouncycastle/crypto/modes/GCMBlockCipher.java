package com.google.bitcoin.bouncycastle.crypto.modes;

import com.google.bitcoin.bouncycastle.crypto.BlockCipher;
import com.google.bitcoin.bouncycastle.crypto.CipherParameters;
import com.google.bitcoin.bouncycastle.crypto.DataLengthException;
import com.google.bitcoin.bouncycastle.crypto.InvalidCipherTextException;
import com.google.bitcoin.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import com.google.bitcoin.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import com.google.bitcoin.bouncycastle.crypto.params.AEADParameters;
import com.google.bitcoin.bouncycastle.crypto.params.KeyParameter;
import com.google.bitcoin.bouncycastle.crypto.params.ParametersWithIV;
import com.google.bitcoin.bouncycastle.crypto.util.Pack;
import com.google.bitcoin.bouncycastle.util.Arrays;

/**
 * Implements the Galois/Counter mode (GCM) detailed in
 * NIST Special Publication 800-38D.
 */
public class GCMBlockCipher
    implements AEADBlockCipher
{
    private static final int BLOCK_SIZE = 16;
    private static final byte[] ZEROES = new byte[BLOCK_SIZE];

    // not final due to a compiler bug 
    private BlockCipher   cipher;
    private GCMMultiplier multiplier;

    // These fields are set by init and not modified by processing
    private boolean             forEncryption;
    private int                 macSize;
    private byte[]              nonce;
    private byte[]              A;
    private KeyParameter        keyParam;
    private byte[]              H;
    private byte[]              initS;
    private byte[]              J0;

    // These fields are modified during processing
    private byte[]      bufBlock;
    private byte[]      macBlock;
    private byte[]      S;
    private byte[]      counter;
    private int         bufOff;
    private long        totalLength;

    public GCMBlockCipher(BlockCipher c)
    {
        this(c, null);
    }

    public GCMBlockCipher(BlockCipher c, GCMMultiplier m)
    {
        if (c.getBlockSize() != BLOCK_SIZE)
        {
            throw new IllegalArgumentException(
                "cipher required with a block size of " + BLOCK_SIZE + ".");
        }

        if (m == null)
        {
            // TODO Consider a static property specifying default multiplier
            m = new Tables8kGCMMultiplier();
        }

        this.cipher = c;
        this.multiplier = m;
    }

    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/GCM";
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        this.macBlock = null;

        if (params instanceof AEADParameters)
        {
            AEADParameters param = (AEADParameters)params;

            nonce = param.getNonce();
            A = param.getAssociatedText();

            int macSizeBits = param.getMacSize();
            if (macSizeBits < 96 || macSizeBits > 128 || macSizeBits % 8 != 0)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }

            macSize = macSizeBits / 8; 
            keyParam = param.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV param = (ParametersWithIV)params;

            nonce = param.getIV();
            A = null;
            macSize = 16;
            keyParam = (KeyParameter)param.getParameters();
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
        }

        int bufLength = forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize); 
        this.bufBlock = new byte[bufLength];

        if (nonce == null || nonce.length < 1)
        {
            throw new IllegalArgumentException("IV must be at least 1 byte");
        }

        if (A == null)
        {
            // Avoid lots of null checks
            A = new byte[0];
        }

        // Cipher always used in forward mode
        cipher.init(true, keyParam);

        // TODO This should be configurable by init parameters
        // (but must be 16 if nonce length not 12) (BLOCK_SIZE?)
//        this.tagLength = 16;

        this.H = new byte[BLOCK_SIZE];
        cipher.processBlock(ZEROES, 0, H, 0);
        multiplier.init(H);

        this.initS = gHASH(A);

        if (nonce.length == 12)
        {
            this.J0 = new byte[16];
            System.arraycopy(nonce, 0, J0, 0, nonce.length);
            this.J0[15] = 0x01;
        }
        else
        {
            this.J0 = gHASH(nonce);
            byte[] X = new byte[16];
            packLength((long)nonce.length * 8, X, 8);
            xor(this.J0, X);
            multiplier.multiplyH(this.J0);
        }

        this.S = Arrays.clone(initS);
        this.counter = Arrays.clone(J0);
        this.bufOff = 0;
        this.totalLength = 0;
    }

    public byte[] getMac()
    {
        return Arrays.clone(macBlock);
    }

    public int getOutputSize(int len)
    {
        if (forEncryption)
        {
             return len + bufOff + macSize;
        }

        return len + bufOff - macSize;
    }

    public int getUpdateOutputSize(int len)
    {
        return ((len + bufOff) / BLOCK_SIZE) * BLOCK_SIZE;
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return process(in, out, outOff);
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        int resultLen = 0;

        for (int i = 0; i != len; i++)
        {
//            resultLen += process(in[inOff + i], out, outOff + resultLen);
            bufBlock[bufOff++] = in[inOff + i];

            if (bufOff == bufBlock.length)
            {
                gCTRBlock(bufBlock, BLOCK_SIZE, out, outOff + resultLen);
                if (!forEncryption)
                {
                    System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, macSize);
                }
//              bufOff = 0;
                bufOff = bufBlock.length - BLOCK_SIZE;
//              return bufBlock.Length;
                resultLen += BLOCK_SIZE;
            }
        }

        return resultLen;
    }

    private int process(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        bufBlock[bufOff++] = in;

        if (bufOff == bufBlock.length)
        {
            gCTRBlock(bufBlock, BLOCK_SIZE, out, outOff);
            if (!forEncryption)
            {
                System.arraycopy(bufBlock, BLOCK_SIZE, bufBlock, 0, macSize);
            }
//            bufOff = 0;
            bufOff = bufBlock.length - BLOCK_SIZE;
//            return bufBlock.length;
            return BLOCK_SIZE;
        }

        return 0;
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        int extra = bufOff;
        if (!forEncryption)
        {
            if (extra < macSize)
            {
                throw new InvalidCipherTextException("data too short");
            }
            extra -= macSize;
        }

        if (extra > 0)
        {
            byte[] tmp = new byte[BLOCK_SIZE];
            System.arraycopy(bufBlock, 0, tmp, 0, extra);
            gCTRBlock(tmp, extra, out, outOff);
        }

        // Final gHASH
        byte[] X = new byte[16];
        packLength((long)A.length * 8, X, 0);
        packLength(totalLength * 8, X, 8);

        xor(S, X);
        multiplier.multiplyH(S);

        // TODO Fix this if tagLength becomes configurable
        // T = MSBt(GCTRk(J0,S))
        byte[] tag = new byte[BLOCK_SIZE];
        cipher.processBlock(J0, 0, tag, 0);
        xor(tag, S);

        int resultLen = extra;

        // We place into macBlock our calculated value for T
        this.macBlock = new byte[macSize];
        System.arraycopy(tag, 0, macBlock, 0, macSize);

        if (forEncryption)
        {
            // Append T to the message
            System.arraycopy(macBlock, 0, out, outOff + bufOff, macSize);
            resultLen += macSize;
        }
        else
        {
            // Retrieve the T value from the message and compare to calculated one
            byte[] msgMac = new byte[macSize];
            System.arraycopy(bufBlock, extra, msgMac, 0, macSize);
            if (!Arrays.constantTimeAreEqual(this.macBlock, msgMac))
            {
                throw new InvalidCipherTextException("mac check in GCM failed");
            }
        }

        reset(false);

        return resultLen;
    }

    public void reset()
    {
        reset(true);
    }

    private void reset(
        boolean clearMac)
    {
        S = Arrays.clone(initS);
        counter = Arrays.clone(J0);
        bufOff = 0;
        totalLength = 0;

        if (bufBlock != null)
        {
            Arrays.fill(bufBlock, (byte)0);
        }

        if (clearMac)
        {
            macBlock = null;
        }

        cipher.reset();
    }

    private void gCTRBlock(byte[] buf, int bufCount, byte[] out, int outOff)
    {
//        inc(counter);
        for (int i = 15; i >= 12; --i)
        {
            byte b = (byte)((counter[i] + 1) & 0xff);
            counter[i] = b;

            if (b != 0)
            {
                break;
            }
        }

        byte[] tmp = new byte[BLOCK_SIZE];
        cipher.processBlock(counter, 0, tmp, 0);

        byte[] hashBytes;
        if (forEncryption)
        {
            System.arraycopy(ZEROES, bufCount, tmp, bufCount, BLOCK_SIZE - bufCount);
            hashBytes = tmp;
        }
        else
        {
            hashBytes = buf;
        }

        for (int i = bufCount - 1; i >= 0; --i)
        {
            tmp[i] ^= buf[i];
            out[outOff + i] = tmp[i];
        }

//        gHASHBlock(hashBytes);
        xor(S, hashBytes);
        multiplier.multiplyH(S);

        totalLength += bufCount;
    }

    private byte[] gHASH(byte[] b)
    {
        byte[] Y = new byte[16];

        for (int pos = 0; pos < b.length; pos += 16)
        {
            byte[] X = new byte[16];
            int num = Math.min(b.length - pos, 16);
            System.arraycopy(b, pos, X, 0, num);
            xor(Y, X);
            multiplier.multiplyH(Y);
        }

        return Y;
    }

//    private void gHASHBlock(byte[] block)
//    {
//        xor(S, block);
//        multiplier.multiplyH(S);
//    }

//    private static void inc(byte[] block)
//    {
//        for (int i = 15; i >= 12; --i)
//        {
//            byte b = (byte)((block[i] + 1) & 0xff);
//            block[i] = b;
//
//            if (b != 0)
//            {
//                break;
//            }
//        }
//    }

    private static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }

    private static void packLength(long count, byte[] bs, int off)
    {
        Pack.intToBigEndian((int)(count >>> 32), bs, off); 
        Pack.intToBigEndian((int)count, bs, off + 4);
    }
}
