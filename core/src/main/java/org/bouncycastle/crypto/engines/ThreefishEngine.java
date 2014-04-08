package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;

/**
 * Implementation of the Threefish tweakable large block cipher in 256, 512 and 1024 bit block
 * sizes.
 * <p>
 * This is the 1.3 version of Threefish defined in the Skein hash function submission to the NIST
 * SHA-3 competition in October 2010.
 * <p>
 * Threefish was designed by Niels Ferguson - Stefan Lucks - Bruce Schneier - Doug Whiting - Mihir
 * Bellare - Tadayoshi Kohno - Jon Callas - Jesse Walker.
 * <p>
 * This implementation inlines all round functions, unrolls 8 rounds, and uses 1.2k of static tables
 * to speed up key schedule injection. <br>
 * 2 x block size state is retained by each cipher instance.
 */
public class ThreefishEngine
    implements BlockCipher
{
    /**
     * 256 bit block size - Threefish-256
     */
    public static final int BLOCKSIZE_256 = 256;
    /**
     * 512 bit block size - Threefish-512
     */
    public static final int BLOCKSIZE_512 = 512;
    /**
     * 1024 bit block size - Threefish-1024
     */
    public static final int BLOCKSIZE_1024 = 1024;

    /**
     * Size of the tweak in bytes (always 128 bit/16 bytes)
     */
    private static final int TWEAK_SIZE_BYTES = 16;
    private static final int TWEAK_SIZE_WORDS = TWEAK_SIZE_BYTES / 8;

    /**
     * Rounds in Threefish-256
     */
    private static final int ROUNDS_256 = 72;
    /**
     * Rounds in Threefish-512
     */
    private static final int ROUNDS_512 = 72;
    /**
     * Rounds in Threefish-1024
     */
    private static final int ROUNDS_1024 = 80;

    /**
     * Max rounds of any of the variants
     */
    private static final int MAX_ROUNDS = ROUNDS_1024;

    /**
     * Key schedule parity constant
     */
    private static final long C_240 = 0x1BD11BDAA9FC1A22L;

    /* Pre-calculated modulo arithmetic tables for key schedule lookups */
    private static int[] MOD9 = new int[MAX_ROUNDS];
    private static int[] MOD17 = new int[MOD9.length];
    private static int[] MOD5 = new int[MOD9.length];
    private static int[] MOD3 = new int[MOD9.length];

    static
    {
        for (int i = 0; i < MOD9.length; i++)
        {
            MOD17[i] = i % 17;
            MOD9[i] = i % 9;
            MOD5[i] = i % 5;
            MOD3[i] = i % 3;
        }
    }

    /**
     * Block size in bytes
     */
    private int blocksizeBytes;

    /**
     * Block size in 64 bit words
     */
    private int blocksizeWords;

    /**
     * Buffer for byte oriented processBytes to call internal word API
     */
    private long[] currentBlock;

    /**
     * Tweak bytes (2 byte t1,t2, calculated t3 and repeat of t1,t2 for modulo free lookup
     */
    private long[] t = new long[5];

    /**
     * Key schedule words
     */
    private long[] kw;

    /**
     * The internal cipher implementation (varies by blocksize)
     */
    private ThreefishCipher cipher;

    private boolean forEncryption;

    /**
     * Constructs a new Threefish cipher, with a specified block size.
     *
     * @param blocksizeBits the block size in bits, one of {@link #BLOCKSIZE_256}, {@link #BLOCKSIZE_512},
     *                      {@link #BLOCKSIZE_1024}.
     */
    public ThreefishEngine(final int blocksizeBits)
    {
        this.blocksizeBytes = (blocksizeBits / 8);
        this.blocksizeWords = (this.blocksizeBytes / 8);
        this.currentBlock = new long[blocksizeWords];

        /*
         * Provide room for original key words, extended key word and repeat of key words for modulo
         * free lookup of key schedule words.
         */
        this.kw = new long[2 * blocksizeWords + 1];

        switch (blocksizeBits)
        {
        case BLOCKSIZE_256:
            cipher = new Threefish256Cipher(kw, t);
            break;
        case BLOCKSIZE_512:
            cipher = new Threefish512Cipher(kw, t);
            break;
        case BLOCKSIZE_1024:
            cipher = new Threefish1024Cipher(kw, t);
            break;
        default:
            throw new IllegalArgumentException(
                "Invalid blocksize - Threefish is defined with block size of 256, 512, or 1024 bits");
        }
    }

    /**
     * Initialise the engine.
     *
     * @param params an instance of {@link TweakableBlockCipherParameters}, or {@link KeyParameter} (to
     *               use a 0 tweak)
     */
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        final byte[] keyBytes;
        final byte[] tweakBytes;

        if (params instanceof TweakableBlockCipherParameters)
        {
            TweakableBlockCipherParameters tParams = (TweakableBlockCipherParameters)params;
            keyBytes = tParams.getKey().getKey();
            tweakBytes = tParams.getTweak();
        }
        else if (params instanceof KeyParameter)
        {
            keyBytes = ((KeyParameter)params).getKey();
            tweakBytes = null;
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameter passed to Threefish init - "
                + params.getClass().getName());
        }

        long[] keyWords = null;
        long[] tweakWords = null;

        if (keyBytes != null)
        {
            if (keyBytes.length != this.blocksizeBytes)
            {
                throw new IllegalArgumentException("Threefish key must be same size as block (" + blocksizeBytes
                    + " bytes)");
            }
            keyWords = new long[blocksizeWords];
            for (int i = 0; i < keyWords.length; i++)
            {
                keyWords[i] = bytesToWord(keyBytes, i * 8);
            }
        }
        if (tweakBytes != null)
        {
            if (tweakBytes.length != TWEAK_SIZE_BYTES)
            {
                throw new IllegalArgumentException("Threefish tweak must be " + TWEAK_SIZE_BYTES + " bytes");
            }
            tweakWords = new long[]{bytesToWord(tweakBytes, 0), bytesToWord(tweakBytes, 8)};
        }
        init(forEncryption, keyWords, tweakWords);
    }

    /**
     * Initialise the engine, specifying the key and tweak directly.
     *
     * @param forEncryption the cipher mode.
     * @param key           the words of the key, or <code>null</code> to use the current key.
     * @param tweak         the 2 word (128 bit) tweak, or <code>null</code> to use the current tweak.
     */
    public void init(boolean forEncryption, final long[] key, final long[] tweak)
    {
        this.forEncryption = forEncryption;
        if (key != null)
        {
            setKey(key);
        }
        if (tweak != null)
        {
            setTweak(tweak);
        }
    }

    private void setKey(long[] key)
    {
        if (key.length != this.blocksizeWords)
        {
            throw new IllegalArgumentException("Threefish key must be same size as block (" + blocksizeWords
                + " words)");
        }

        /*
         * Full subkey schedule is deferred to execution to avoid per cipher overhead (10k for 512,
         * 20k for 1024).
         * 
         * Key and tweak word sequences are repeated, and static MOD17/MOD9/MOD5/MOD3 calculations
         * used, to avoid expensive mod computations during cipher operation.
         */

        long knw = C_240;
        for (int i = 0; i < blocksizeWords; i++)
        {
            kw[i] = key[i];
            knw = knw ^ kw[i];
        }
        kw[blocksizeWords] = knw;
        System.arraycopy(kw, 0, kw, blocksizeWords + 1, blocksizeWords);
    }

    private void setTweak(long[] tweak)
    {
        if (tweak.length != TWEAK_SIZE_WORDS)
        {
            throw new IllegalArgumentException("Tweak must be " + TWEAK_SIZE_WORDS + " words.");
        }

        /*
         * Tweak schedule partially repeated to avoid mod computations during cipher operation
         */
        t[0] = tweak[0];
        t[1] = tweak[1];
        t[2] = t[0] ^ t[1];
        t[3] = t[0];
        t[4] = t[1];
    }

    public String getAlgorithmName()
    {
        return "Threefish-" + (blocksizeBytes * 8);
    }

    public int getBlockSize()
    {
        return blocksizeBytes;
    }

    public void reset()
    {
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException,
        IllegalStateException
    {
        if ((outOff + blocksizeBytes) > out.length)
        {
            throw new DataLengthException("Output buffer too short");
        }

        if ((inOff + blocksizeBytes) > in.length)
        {
            throw new DataLengthException("Input buffer too short");
        }

        for (int i = 0; i < blocksizeBytes; i += 8)
        {
            currentBlock[i >> 3] = bytesToWord(in, inOff + i);
        }
        processBlock(this.currentBlock, this.currentBlock);
        for (int i = 0; i < blocksizeBytes; i += 8)
        {
            wordToBytes(this.currentBlock[i >> 3], out, outOff + i);
        }

        return blocksizeBytes;
    }

    /**
     * Process a block of data represented as 64 bit words.
     *
     * @param in  a block sized buffer of words to process.
     * @param out a block sized buffer of words to receive the output of the operation.
     * @return the number of 8 byte words processed (which will be the same as the block size).
     * @throws DataLengthException if either the input or output is not block sized.
     * @throws IllegalStateException if this engine is not initialised.
     */
    public int processBlock(long[] in, long[] out)
        throws DataLengthException, IllegalStateException
    {
        if (kw[blocksizeWords] == 0)
        {
            throw new IllegalStateException("Threefish engine not initialised");
        }

        if (in.length != blocksizeWords)
        {
            throw new DataLengthException("Input buffer too short");
        }
        if (out.length != blocksizeWords)
        {
            throw new DataLengthException("Output buffer too short");
        }

        if (forEncryption)
        {
            cipher.encryptBlock(in, out);
        }
        else
        {
            cipher.decryptBlock(in, out);
        }

        return blocksizeWords;
    }

    /**
     * Read a single 64 bit word from input in LSB first order.
     */
    // At least package protected for efficient access from inner class
    public static long bytesToWord(final byte[] bytes, final int off)
    {
        if ((off + 8) > bytes.length)
        {
            // Help the JIT avoid index checks
            throw new IllegalArgumentException();
        }

        long word = 0;
        int index = off;

        word = (bytes[index++] & 0xffL);
        word |= (bytes[index++] & 0xffL) << 8;
        word |= (bytes[index++] & 0xffL) << 16;
        word |= (bytes[index++] & 0xffL) << 24;
        word |= (bytes[index++] & 0xffL) << 32;
        word |= (bytes[index++] & 0xffL) << 40;
        word |= (bytes[index++] & 0xffL) << 48;
        word |= (bytes[index++] & 0xffL) << 56;

        return word;
    }

    /**
     * Write a 64 bit word to output in LSB first order.
     */
    // At least package protected for efficient access from inner class
    public static void wordToBytes(final long word, final byte[] bytes, final int off)
    {
        if ((off + 8) > bytes.length)
        {
            // Help the JIT avoid index checks
            throw new IllegalArgumentException();
        }
        int index = off;

        bytes[index++] = (byte)word;
        bytes[index++] = (byte)(word >> 8);
        bytes[index++] = (byte)(word >> 16);
        bytes[index++] = (byte)(word >> 24);
        bytes[index++] = (byte)(word >> 32);
        bytes[index++] = (byte)(word >> 40);
        bytes[index++] = (byte)(word >> 48);
        bytes[index++] = (byte)(word >> 56);
    }

    /**
     * Rotate left + xor part of the mix operation.
     */
    // Package protected for efficient access from inner class
    static long rotlXor(long x, int n, long xor)
    {
        return ((x << n) | (x >>> -n)) ^ xor;
    }

    /**
     * Rotate xor + rotate right part of the unmix operation.
     */
    // Package protected for efficient access from inner class
    static long xorRotr(long x, int n, long xor)
    {
        long xored = x ^ xor;
        return (xored >>> n) | (xored << -n);
    }

    private static abstract class ThreefishCipher
    {
        /**
         * The extended + repeated tweak words
         */
        protected final long[] t;
        /**
         * The extended + repeated key words
         */
        protected final long[] kw;

        protected ThreefishCipher(final long[] kw, final long[] t)
        {
            this.kw = kw;
            this.t = t;
        }

        abstract void encryptBlock(long[] block, long[] out);

        abstract void decryptBlock(long[] block, long[] out);

    }

    private static final class Threefish256Cipher
        extends ThreefishCipher
    {
        /**
         * Mix rotation constants defined in Skein 1.3 specification
         */
        private static final int ROTATION_0_0 = 14, ROTATION_0_1 = 16;
        private static final int ROTATION_1_0 = 52, ROTATION_1_1 = 57;
        private static final int ROTATION_2_0 = 23, ROTATION_2_1 = 40;
        private static final int ROTATION_3_0 = 5, ROTATION_3_1 = 37;

        private static final int ROTATION_4_0 = 25, ROTATION_4_1 = 33;
        private static final int ROTATION_5_0 = 46, ROTATION_5_1 = 12;
        private static final int ROTATION_6_0 = 58, ROTATION_6_1 = 22;
        private static final int ROTATION_7_0 = 32, ROTATION_7_1 = 32;

        public Threefish256Cipher(long[] kw, long[] t)
        {
            super(kw, t);
        }

        void encryptBlock(long[] block, long[] out)
        {
            final long[] kw = this.kw;
            final long[] t = this.t;
            final int[] mod5 = MOD5;
            final int[] mod3 = MOD3;

            /* Help the JIT avoid index bounds checks */
            if (kw.length != 9)
            {
                throw new IllegalArgumentException();
            }
            if (t.length != 5)
            {
                throw new IllegalArgumentException();
            }

            /*
             * Read 4 words of plaintext data, not using arrays for cipher state
             */
            long b0 = block[0];
            long b1 = block[1];
            long b2 = block[2];
            long b3 = block[3];

            /*
             * First subkey injection.
             */
            b0 += kw[0];
            b1 += kw[1] + t[0];
            b2 += kw[2] + t[1];
            b3 += kw[3];

            /*
             * Rounds loop, unrolled to 8 rounds per iteration.
             * 
             * Unrolling to multiples of 4 avoids the mod 4 check for key injection, and allows
             * inlining of the permutations, which cycle every of 2 rounds (avoiding array
             * index/lookup).
             * 
             * Unrolling to multiples of 8 avoids the mod 8 rotation constant lookup, and allows
             * inlining constant rotation values (avoiding array index/lookup).
             */

            for (int d = 1; d < (ROUNDS_256 / 4); d += 2)
            {
                final int dm5 = mod5[d];
                final int dm3 = mod3[d];

                /*
                 * 4 rounds of mix and permute.
                 * 
                 * Permute schedule has a 2 round cycle, so permutes are inlined in the mix
                 * operations in each 4 round block.
                 */
                b1 = rotlXor(b1, ROTATION_0_0, b0 += b1);
                b3 = rotlXor(b3, ROTATION_0_1, b2 += b3);

                b3 = rotlXor(b3, ROTATION_1_0, b0 += b3);
                b1 = rotlXor(b1, ROTATION_1_1, b2 += b1);

                b1 = rotlXor(b1, ROTATION_2_0, b0 += b1);
                b3 = rotlXor(b3, ROTATION_2_1, b2 += b3);

                b3 = rotlXor(b3, ROTATION_3_0, b0 += b3);
                b1 = rotlXor(b1, ROTATION_3_1, b2 += b1);

                /*
                 * Subkey injection for first 4 rounds.
                 */
                b0 += kw[dm5];
                b1 += kw[dm5 + 1] + t[dm3];
                b2 += kw[dm5 + 2] + t[dm3 + 1];
                b3 += kw[dm5 + 3] + d;

                /*
                 * 4 more rounds of mix/permute
                 */
                b1 = rotlXor(b1, ROTATION_4_0, b0 += b1);
                b3 = rotlXor(b3, ROTATION_4_1, b2 += b3);

                b3 = rotlXor(b3, ROTATION_5_0, b0 += b3);
                b1 = rotlXor(b1, ROTATION_5_1, b2 += b1);

                b1 = rotlXor(b1, ROTATION_6_0, b0 += b1);
                b3 = rotlXor(b3, ROTATION_6_1, b2 += b3);

                b3 = rotlXor(b3, ROTATION_7_0, b0 += b3);
                b1 = rotlXor(b1, ROTATION_7_1, b2 += b1);

                /*
                 * Subkey injection for next 4 rounds.
                 */
                b0 += kw[dm5 + 1];
                b1 += kw[dm5 + 2] + t[dm3 + 1];
                b2 += kw[dm5 + 3] + t[dm3 + 2];
                b3 += kw[dm5 + 4] + d + 1;
            }

            /*
             * Output cipher state.
             */
            out[0] = b0;
            out[1] = b1;
            out[2] = b2;
            out[3] = b3;
        }

        void decryptBlock(long[] block, long[] state)
        {
            final long[] kw = this.kw;
            final long[] t = this.t;
            final int[] mod5 = MOD5;
            final int[] mod3 = MOD3;

            /* Help the JIT avoid index bounds checks */
            if (kw.length != 9)
            {
                throw new IllegalArgumentException();
            }
            if (t.length != 5)
            {
                throw new IllegalArgumentException();
            }

            long b0 = block[0];
            long b1 = block[1];
            long b2 = block[2];
            long b3 = block[3];

            for (int d = (ROUNDS_256 / 4) - 1; d >= 1; d -= 2)
            {
                final int dm5 = mod5[d];
                final int dm3 = mod3[d];

                /* Reverse key injection for second 4 rounds */
                b0 -= kw[dm5 + 1];
                b1 -= kw[dm5 + 2] + t[dm3 + 1];
                b2 -= kw[dm5 + 3] + t[dm3 + 2];
                b3 -= kw[dm5 + 4] + d + 1;

                /* Reverse second 4 mix/permute rounds */

                b3 = xorRotr(b3, ROTATION_7_0, b0);
                b0 -= b3;
                b1 = xorRotr(b1, ROTATION_7_1, b2);
                b2 -= b1;

                b1 = xorRotr(b1, ROTATION_6_0, b0);
                b0 -= b1;
                b3 = xorRotr(b3, ROTATION_6_1, b2);
                b2 -= b3;

                b3 = xorRotr(b3, ROTATION_5_0, b0);
                b0 -= b3;
                b1 = xorRotr(b1, ROTATION_5_1, b2);
                b2 -= b1;

                b1 = xorRotr(b1, ROTATION_4_0, b0);
                b0 -= b1;
                b3 = xorRotr(b3, ROTATION_4_1, b2);
                b2 -= b3;

                /* Reverse key injection for first 4 rounds */
                b0 -= kw[dm5];
                b1 -= kw[dm5 + 1] + t[dm3];
                b2 -= kw[dm5 + 2] + t[dm3 + 1];
                b3 -= kw[dm5 + 3] + d;

                /* Reverse first 4 mix/permute rounds */
                b3 = xorRotr(b3, ROTATION_3_0, b0);
                b0 -= b3;
                b1 = xorRotr(b1, ROTATION_3_1, b2);
                b2 -= b1;

                b1 = xorRotr(b1, ROTATION_2_0, b0);
                b0 -= b1;
                b3 = xorRotr(b3, ROTATION_2_1, b2);
                b2 -= b3;

                b3 = xorRotr(b3, ROTATION_1_0, b0);
                b0 -= b3;
                b1 = xorRotr(b1, ROTATION_1_1, b2);
                b2 -= b1;

                b1 = xorRotr(b1, ROTATION_0_0, b0);
                b0 -= b1;
                b3 = xorRotr(b3, ROTATION_0_1, b2);
                b2 -= b3;
            }

            /*
             * First subkey uninjection.
             */
            b0 -= kw[0];
            b1 -= kw[1] + t[0];
            b2 -= kw[2] + t[1];
            b3 -= kw[3];

            /*
             * Output cipher state.
             */
            state[0] = b0;
            state[1] = b1;
            state[2] = b2;
            state[3] = b3;
        }

    }

    private static final class Threefish512Cipher
        extends ThreefishCipher
    {
        /**
         * Mix rotation constants defined in Skein 1.3 specification
         */
        private static final int ROTATION_0_0 = 46, ROTATION_0_1 = 36, ROTATION_0_2 = 19, ROTATION_0_3 = 37;
        private static final int ROTATION_1_0 = 33, ROTATION_1_1 = 27, ROTATION_1_2 = 14, ROTATION_1_3 = 42;
        private static final int ROTATION_2_0 = 17, ROTATION_2_1 = 49, ROTATION_2_2 = 36, ROTATION_2_3 = 39;
        private static final int ROTATION_3_0 = 44, ROTATION_3_1 = 9, ROTATION_3_2 = 54, ROTATION_3_3 = 56;

        private static final int ROTATION_4_0 = 39, ROTATION_4_1 = 30, ROTATION_4_2 = 34, ROTATION_4_3 = 24;
        private static final int ROTATION_5_0 = 13, ROTATION_5_1 = 50, ROTATION_5_2 = 10, ROTATION_5_3 = 17;
        private static final int ROTATION_6_0 = 25, ROTATION_6_1 = 29, ROTATION_6_2 = 39, ROTATION_6_3 = 43;
        private static final int ROTATION_7_0 = 8, ROTATION_7_1 = 35, ROTATION_7_2 = 56, ROTATION_7_3 = 22;

        protected Threefish512Cipher(long[] kw, long[] t)
        {
            super(kw, t);
        }

        public void encryptBlock(long[] block, long[] out)
        {
            final long[] kw = this.kw;
            final long[] t = this.t;
            final int[] mod9 = MOD9;
            final int[] mod3 = MOD3;

            /* Help the JIT avoid index bounds checks */
            if (kw.length != 17)
            {
                throw new IllegalArgumentException();
            }
            if (t.length != 5)
            {
                throw new IllegalArgumentException();
            }

            /*
             * Read 8 words of plaintext data, not using arrays for cipher state
             */
            long b0 = block[0];
            long b1 = block[1];
            long b2 = block[2];
            long b3 = block[3];
            long b4 = block[4];
            long b5 = block[5];
            long b6 = block[6];
            long b7 = block[7];

            /*
             * First subkey injection.
             */
            b0 += kw[0];
            b1 += kw[1];
            b2 += kw[2];
            b3 += kw[3];
            b4 += kw[4];
            b5 += kw[5] + t[0];
            b6 += kw[6] + t[1];
            b7 += kw[7];

            /*
             * Rounds loop, unrolled to 8 rounds per iteration.
             * 
             * Unrolling to multiples of 4 avoids the mod 4 check for key injection, and allows
             * inlining of the permutations, which cycle every of 4 rounds (avoiding array
             * index/lookup).
             * 
             * Unrolling to multiples of 8 avoids the mod 8 rotation constant lookup, and allows
             * inlining constant rotation values (avoiding array index/lookup).
             */

            for (int d = 1; d < (ROUNDS_512 / 4); d += 2)
            {
                final int dm9 = mod9[d];
                final int dm3 = mod3[d];

                /*
                 * 4 rounds of mix and permute.
                 * 
                 * Permute schedule has a 4 round cycle, so permutes are inlined in the mix
                 * operations in each 4 round block.
                 */
                b1 = rotlXor(b1, ROTATION_0_0, b0 += b1);
                b3 = rotlXor(b3, ROTATION_0_1, b2 += b3);
                b5 = rotlXor(b5, ROTATION_0_2, b4 += b5);
                b7 = rotlXor(b7, ROTATION_0_3, b6 += b7);

                b1 = rotlXor(b1, ROTATION_1_0, b2 += b1);
                b7 = rotlXor(b7, ROTATION_1_1, b4 += b7);
                b5 = rotlXor(b5, ROTATION_1_2, b6 += b5);
                b3 = rotlXor(b3, ROTATION_1_3, b0 += b3);

                b1 = rotlXor(b1, ROTATION_2_0, b4 += b1);
                b3 = rotlXor(b3, ROTATION_2_1, b6 += b3);
                b5 = rotlXor(b5, ROTATION_2_2, b0 += b5);
                b7 = rotlXor(b7, ROTATION_2_3, b2 += b7);

                b1 = rotlXor(b1, ROTATION_3_0, b6 += b1);
                b7 = rotlXor(b7, ROTATION_3_1, b0 += b7);
                b5 = rotlXor(b5, ROTATION_3_2, b2 += b5);
                b3 = rotlXor(b3, ROTATION_3_3, b4 += b3);

                /*
                 * Subkey injection for first 4 rounds.
                 */
                b0 += kw[dm9];
                b1 += kw[dm9 + 1];
                b2 += kw[dm9 + 2];
                b3 += kw[dm9 + 3];
                b4 += kw[dm9 + 4];
                b5 += kw[dm9 + 5] + t[dm3];
                b6 += kw[dm9 + 6] + t[dm3 + 1];
                b7 += kw[dm9 + 7] + d;

                /*
                 * 4 more rounds of mix/permute
                 */
                b1 = rotlXor(b1, ROTATION_4_0, b0 += b1);
                b3 = rotlXor(b3, ROTATION_4_1, b2 += b3);
                b5 = rotlXor(b5, ROTATION_4_2, b4 += b5);
                b7 = rotlXor(b7, ROTATION_4_3, b6 += b7);

                b1 = rotlXor(b1, ROTATION_5_0, b2 += b1);
                b7 = rotlXor(b7, ROTATION_5_1, b4 += b7);
                b5 = rotlXor(b5, ROTATION_5_2, b6 += b5);
                b3 = rotlXor(b3, ROTATION_5_3, b0 += b3);

                b1 = rotlXor(b1, ROTATION_6_0, b4 += b1);
                b3 = rotlXor(b3, ROTATION_6_1, b6 += b3);
                b5 = rotlXor(b5, ROTATION_6_2, b0 += b5);
                b7 = rotlXor(b7, ROTATION_6_3, b2 += b7);

                b1 = rotlXor(b1, ROTATION_7_0, b6 += b1);
                b7 = rotlXor(b7, ROTATION_7_1, b0 += b7);
                b5 = rotlXor(b5, ROTATION_7_2, b2 += b5);
                b3 = rotlXor(b3, ROTATION_7_3, b4 += b3);

                /*
                 * Subkey injection for next 4 rounds.
                 */
                b0 += kw[dm9 + 1];
                b1 += kw[dm9 + 2];
                b2 += kw[dm9 + 3];
                b3 += kw[dm9 + 4];
                b4 += kw[dm9 + 5];
                b5 += kw[dm9 + 6] + t[dm3 + 1];
                b6 += kw[dm9 + 7] + t[dm3 + 2];
                b7 += kw[dm9 + 8] + d + 1;
            }

            /*
             * Output cipher state.
             */
            out[0] = b0;
            out[1] = b1;
            out[2] = b2;
            out[3] = b3;
            out[4] = b4;
            out[5] = b5;
            out[6] = b6;
            out[7] = b7;
        }

        public void decryptBlock(long[] block, long[] state)
        {
            final long[] kw = this.kw;
            final long[] t = this.t;
            final int[] mod9 = MOD9;
            final int[] mod3 = MOD3;

            /* Help the JIT avoid index bounds checks */
            if (kw.length != 17)
            {
                throw new IllegalArgumentException();
            }
            if (t.length != 5)
            {
                throw new IllegalArgumentException();
            }

            long b0 = block[0];
            long b1 = block[1];
            long b2 = block[2];
            long b3 = block[3];
            long b4 = block[4];
            long b5 = block[5];
            long b6 = block[6];
            long b7 = block[7];

            for (int d = (ROUNDS_512 / 4) - 1; d >= 1; d -= 2)
            {
                final int dm9 = mod9[d];
                final int dm3 = mod3[d];

                /* Reverse key injection for second 4 rounds */
                b0 -= kw[dm9 + 1];
                b1 -= kw[dm9 + 2];
                b2 -= kw[dm9 + 3];
                b3 -= kw[dm9 + 4];
                b4 -= kw[dm9 + 5];
                b5 -= kw[dm9 + 6] + t[dm3 + 1];
                b6 -= kw[dm9 + 7] + t[dm3 + 2];
                b7 -= kw[dm9 + 8] + d + 1;

                /* Reverse second 4 mix/permute rounds */

                b1 = xorRotr(b1, ROTATION_7_0, b6);
                b6 -= b1;
                b7 = xorRotr(b7, ROTATION_7_1, b0);
                b0 -= b7;
                b5 = xorRotr(b5, ROTATION_7_2, b2);
                b2 -= b5;
                b3 = xorRotr(b3, ROTATION_7_3, b4);
                b4 -= b3;

                b1 = xorRotr(b1, ROTATION_6_0, b4);
                b4 -= b1;
                b3 = xorRotr(b3, ROTATION_6_1, b6);
                b6 -= b3;
                b5 = xorRotr(b5, ROTATION_6_2, b0);
                b0 -= b5;
                b7 = xorRotr(b7, ROTATION_6_3, b2);
                b2 -= b7;

                b1 = xorRotr(b1, ROTATION_5_0, b2);
                b2 -= b1;
                b7 = xorRotr(b7, ROTATION_5_1, b4);
                b4 -= b7;
                b5 = xorRotr(b5, ROTATION_5_2, b6);
                b6 -= b5;
                b3 = xorRotr(b3, ROTATION_5_3, b0);
                b0 -= b3;

                b1 = xorRotr(b1, ROTATION_4_0, b0);
                b0 -= b1;
                b3 = xorRotr(b3, ROTATION_4_1, b2);
                b2 -= b3;
                b5 = xorRotr(b5, ROTATION_4_2, b4);
                b4 -= b5;
                b7 = xorRotr(b7, ROTATION_4_3, b6);
                b6 -= b7;

                /* Reverse key injection for first 4 rounds */
                b0 -= kw[dm9];
                b1 -= kw[dm9 + 1];
                b2 -= kw[dm9 + 2];
                b3 -= kw[dm9 + 3];
                b4 -= kw[dm9 + 4];
                b5 -= kw[dm9 + 5] + t[dm3];
                b6 -= kw[dm9 + 6] + t[dm3 + 1];
                b7 -= kw[dm9 + 7] + d;

                /* Reverse first 4 mix/permute rounds */
                b1 = xorRotr(b1, ROTATION_3_0, b6);
                b6 -= b1;
                b7 = xorRotr(b7, ROTATION_3_1, b0);
                b0 -= b7;
                b5 = xorRotr(b5, ROTATION_3_2, b2);
                b2 -= b5;
                b3 = xorRotr(b3, ROTATION_3_3, b4);
                b4 -= b3;

                b1 = xorRotr(b1, ROTATION_2_0, b4);
                b4 -= b1;
                b3 = xorRotr(b3, ROTATION_2_1, b6);
                b6 -= b3;
                b5 = xorRotr(b5, ROTATION_2_2, b0);
                b0 -= b5;
                b7 = xorRotr(b7, ROTATION_2_3, b2);
                b2 -= b7;

                b1 = xorRotr(b1, ROTATION_1_0, b2);
                b2 -= b1;
                b7 = xorRotr(b7, ROTATION_1_1, b4);
                b4 -= b7;
                b5 = xorRotr(b5, ROTATION_1_2, b6);
                b6 -= b5;
                b3 = xorRotr(b3, ROTATION_1_3, b0);
                b0 -= b3;

                b1 = xorRotr(b1, ROTATION_0_0, b0);
                b0 -= b1;
                b3 = xorRotr(b3, ROTATION_0_1, b2);
                b2 -= b3;
                b5 = xorRotr(b5, ROTATION_0_2, b4);
                b4 -= b5;
                b7 = xorRotr(b7, ROTATION_0_3, b6);
                b6 -= b7;
            }

            /*
             * First subkey uninjection.
             */
            b0 -= kw[0];
            b1 -= kw[1];
            b2 -= kw[2];
            b3 -= kw[3];
            b4 -= kw[4];
            b5 -= kw[5] + t[0];
            b6 -= kw[6] + t[1];
            b7 -= kw[7];

            /*
             * Output cipher state.
             */
            state[0] = b0;
            state[1] = b1;
            state[2] = b2;
            state[3] = b3;
            state[4] = b4;
            state[5] = b5;
            state[6] = b6;
            state[7] = b7;
        }
    }

    private static final class Threefish1024Cipher
        extends ThreefishCipher
    {
        /**
         * Mix rotation constants defined in Skein 1.3 specification
         */
        private static final int ROTATION_0_0 = 24, ROTATION_0_1 = 13, ROTATION_0_2 = 8, ROTATION_0_3 = 47;
        private static final int ROTATION_0_4 = 8, ROTATION_0_5 = 17, ROTATION_0_6 = 22, ROTATION_0_7 = 37;
        private static final int ROTATION_1_0 = 38, ROTATION_1_1 = 19, ROTATION_1_2 = 10, ROTATION_1_3 = 55;
        private static final int ROTATION_1_4 = 49, ROTATION_1_5 = 18, ROTATION_1_6 = 23, ROTATION_1_7 = 52;
        private static final int ROTATION_2_0 = 33, ROTATION_2_1 = 4, ROTATION_2_2 = 51, ROTATION_2_3 = 13;
        private static final int ROTATION_2_4 = 34, ROTATION_2_5 = 41, ROTATION_2_6 = 59, ROTATION_2_7 = 17;
        private static final int ROTATION_3_0 = 5, ROTATION_3_1 = 20, ROTATION_3_2 = 48, ROTATION_3_3 = 41;
        private static final int ROTATION_3_4 = 47, ROTATION_3_5 = 28, ROTATION_3_6 = 16, ROTATION_3_7 = 25;

        private static final int ROTATION_4_0 = 41, ROTATION_4_1 = 9, ROTATION_4_2 = 37, ROTATION_4_3 = 31;
        private static final int ROTATION_4_4 = 12, ROTATION_4_5 = 47, ROTATION_4_6 = 44, ROTATION_4_7 = 30;
        private static final int ROTATION_5_0 = 16, ROTATION_5_1 = 34, ROTATION_5_2 = 56, ROTATION_5_3 = 51;
        private static final int ROTATION_5_4 = 4, ROTATION_5_5 = 53, ROTATION_5_6 = 42, ROTATION_5_7 = 41;
        private static final int ROTATION_6_0 = 31, ROTATION_6_1 = 44, ROTATION_6_2 = 47, ROTATION_6_3 = 46;
        private static final int ROTATION_6_4 = 19, ROTATION_6_5 = 42, ROTATION_6_6 = 44, ROTATION_6_7 = 25;
        private static final int ROTATION_7_0 = 9, ROTATION_7_1 = 48, ROTATION_7_2 = 35, ROTATION_7_3 = 52;
        private static final int ROTATION_7_4 = 23, ROTATION_7_5 = 31, ROTATION_7_6 = 37, ROTATION_7_7 = 20;

        public Threefish1024Cipher(long[] kw, long[] t)
        {
            super(kw, t);
        }

        void encryptBlock(long[] block, long[] out)
        {
            final long[] kw = this.kw;
            final long[] t = this.t;
            final int[] mod17 = MOD17;
            final int[] mod3 = MOD3;

            /* Help the JIT avoid index bounds checks */
            if (kw.length != 33)
            {
                throw new IllegalArgumentException();
            }
            if (t.length != 5)
            {
                throw new IllegalArgumentException();
            }

            /*
             * Read 16 words of plaintext data, not using arrays for cipher state
             */
            long b0 = block[0];
            long b1 = block[1];
            long b2 = block[2];
            long b3 = block[3];
            long b4 = block[4];
            long b5 = block[5];
            long b6 = block[6];
            long b7 = block[7];
            long b8 = block[8];
            long b9 = block[9];
            long b10 = block[10];
            long b11 = block[11];
            long b12 = block[12];
            long b13 = block[13];
            long b14 = block[14];
            long b15 = block[15];

            /*
             * First subkey injection.
             */
            b0 += kw[0];
            b1 += kw[1];
            b2 += kw[2];
            b3 += kw[3];
            b4 += kw[4];
            b5 += kw[5];
            b6 += kw[6];
            b7 += kw[7];
            b8 += kw[8];
            b9 += kw[9];
            b10 += kw[10];
            b11 += kw[11];
            b12 += kw[12];
            b13 += kw[13] + t[0];
            b14 += kw[14] + t[1];
            b15 += kw[15];

            /*
             * Rounds loop, unrolled to 8 rounds per iteration.
             * 
             * Unrolling to multiples of 4 avoids the mod 4 check for key injection, and allows
             * inlining of the permutations, which cycle every of 4 rounds (avoiding array
             * index/lookup).
             * 
             * Unrolling to multiples of 8 avoids the mod 8 rotation constant lookup, and allows
             * inlining constant rotation values (avoiding array index/lookup).
             */

            for (int d = 1; d < (ROUNDS_1024 / 4); d += 2)
            {
                final int dm17 = mod17[d];
                final int dm3 = mod3[d];

                /*
                 * 4 rounds of mix and permute.
                 * 
                 * Permute schedule has a 4 round cycle, so permutes are inlined in the mix
                 * operations in each 4 round block.
                 */
                b1 = rotlXor(b1, ROTATION_0_0, b0 += b1);
                b3 = rotlXor(b3, ROTATION_0_1, b2 += b3);
                b5 = rotlXor(b5, ROTATION_0_2, b4 += b5);
                b7 = rotlXor(b7, ROTATION_0_3, b6 += b7);
                b9 = rotlXor(b9, ROTATION_0_4, b8 += b9);
                b11 = rotlXor(b11, ROTATION_0_5, b10 += b11);
                b13 = rotlXor(b13, ROTATION_0_6, b12 += b13);
                b15 = rotlXor(b15, ROTATION_0_7, b14 += b15);

                b9 = rotlXor(b9, ROTATION_1_0, b0 += b9);
                b13 = rotlXor(b13, ROTATION_1_1, b2 += b13);
                b11 = rotlXor(b11, ROTATION_1_2, b6 += b11);
                b15 = rotlXor(b15, ROTATION_1_3, b4 += b15);
                b7 = rotlXor(b7, ROTATION_1_4, b10 += b7);
                b3 = rotlXor(b3, ROTATION_1_5, b12 += b3);
                b5 = rotlXor(b5, ROTATION_1_6, b14 += b5);
                b1 = rotlXor(b1, ROTATION_1_7, b8 += b1);

                b7 = rotlXor(b7, ROTATION_2_0, b0 += b7);
                b5 = rotlXor(b5, ROTATION_2_1, b2 += b5);
                b3 = rotlXor(b3, ROTATION_2_2, b4 += b3);
                b1 = rotlXor(b1, ROTATION_2_3, b6 += b1);
                b15 = rotlXor(b15, ROTATION_2_4, b12 += b15);
                b13 = rotlXor(b13, ROTATION_2_5, b14 += b13);
                b11 = rotlXor(b11, ROTATION_2_6, b8 += b11);
                b9 = rotlXor(b9, ROTATION_2_7, b10 += b9);

                b15 = rotlXor(b15, ROTATION_3_0, b0 += b15);
                b11 = rotlXor(b11, ROTATION_3_1, b2 += b11);
                b13 = rotlXor(b13, ROTATION_3_2, b6 += b13);
                b9 = rotlXor(b9, ROTATION_3_3, b4 += b9);
                b1 = rotlXor(b1, ROTATION_3_4, b14 += b1);
                b5 = rotlXor(b5, ROTATION_3_5, b8 += b5);
                b3 = rotlXor(b3, ROTATION_3_6, b10 += b3);
                b7 = rotlXor(b7, ROTATION_3_7, b12 += b7);

                /*
                 * Subkey injection for first 4 rounds.
                 */
                b0 += kw[dm17];
                b1 += kw[dm17 + 1];
                b2 += kw[dm17 + 2];
                b3 += kw[dm17 + 3];
                b4 += kw[dm17 + 4];
                b5 += kw[dm17 + 5];
                b6 += kw[dm17 + 6];
                b7 += kw[dm17 + 7];
                b8 += kw[dm17 + 8];
                b9 += kw[dm17 + 9];
                b10 += kw[dm17 + 10];
                b11 += kw[dm17 + 11];
                b12 += kw[dm17 + 12];
                b13 += kw[dm17 + 13] + t[dm3];
                b14 += kw[dm17 + 14] + t[dm3 + 1];
                b15 += kw[dm17 + 15] + d;

                /*
                 * 4 more rounds of mix/permute
                 */
                b1 = rotlXor(b1, ROTATION_4_0, b0 += b1);
                b3 = rotlXor(b3, ROTATION_4_1, b2 += b3);
                b5 = rotlXor(b5, ROTATION_4_2, b4 += b5);
                b7 = rotlXor(b7, ROTATION_4_3, b6 += b7);
                b9 = rotlXor(b9, ROTATION_4_4, b8 += b9);
                b11 = rotlXor(b11, ROTATION_4_5, b10 += b11);
                b13 = rotlXor(b13, ROTATION_4_6, b12 += b13);
                b15 = rotlXor(b15, ROTATION_4_7, b14 += b15);

                b9 = rotlXor(b9, ROTATION_5_0, b0 += b9);
                b13 = rotlXor(b13, ROTATION_5_1, b2 += b13);
                b11 = rotlXor(b11, ROTATION_5_2, b6 += b11);
                b15 = rotlXor(b15, ROTATION_5_3, b4 += b15);
                b7 = rotlXor(b7, ROTATION_5_4, b10 += b7);
                b3 = rotlXor(b3, ROTATION_5_5, b12 += b3);
                b5 = rotlXor(b5, ROTATION_5_6, b14 += b5);
                b1 = rotlXor(b1, ROTATION_5_7, b8 += b1);

                b7 = rotlXor(b7, ROTATION_6_0, b0 += b7);
                b5 = rotlXor(b5, ROTATION_6_1, b2 += b5);
                b3 = rotlXor(b3, ROTATION_6_2, b4 += b3);
                b1 = rotlXor(b1, ROTATION_6_3, b6 += b1);
                b15 = rotlXor(b15, ROTATION_6_4, b12 += b15);
                b13 = rotlXor(b13, ROTATION_6_5, b14 += b13);
                b11 = rotlXor(b11, ROTATION_6_6, b8 += b11);
                b9 = rotlXor(b9, ROTATION_6_7, b10 += b9);

                b15 = rotlXor(b15, ROTATION_7_0, b0 += b15);
                b11 = rotlXor(b11, ROTATION_7_1, b2 += b11);
                b13 = rotlXor(b13, ROTATION_7_2, b6 += b13);
                b9 = rotlXor(b9, ROTATION_7_3, b4 += b9);
                b1 = rotlXor(b1, ROTATION_7_4, b14 += b1);
                b5 = rotlXor(b5, ROTATION_7_5, b8 += b5);
                b3 = rotlXor(b3, ROTATION_7_6, b10 += b3);
                b7 = rotlXor(b7, ROTATION_7_7, b12 += b7);

                /*
                 * Subkey injection for next 4 rounds.
                 */
                b0 += kw[dm17 + 1];
                b1 += kw[dm17 + 2];
                b2 += kw[dm17 + 3];
                b3 += kw[dm17 + 4];
                b4 += kw[dm17 + 5];
                b5 += kw[dm17 + 6];
                b6 += kw[dm17 + 7];
                b7 += kw[dm17 + 8];
                b8 += kw[dm17 + 9];
                b9 += kw[dm17 + 10];
                b10 += kw[dm17 + 11];
                b11 += kw[dm17 + 12];
                b12 += kw[dm17 + 13];
                b13 += kw[dm17 + 14] + t[dm3 + 1];
                b14 += kw[dm17 + 15] + t[dm3 + 2];
                b15 += kw[dm17 + 16] + d + 1;

            }

            /*
             * Output cipher state.
             */
            out[0] = b0;
            out[1] = b1;
            out[2] = b2;
            out[3] = b3;
            out[4] = b4;
            out[5] = b5;
            out[6] = b6;
            out[7] = b7;
            out[8] = b8;
            out[9] = b9;
            out[10] = b10;
            out[11] = b11;
            out[12] = b12;
            out[13] = b13;
            out[14] = b14;
            out[15] = b15;
        }

        void decryptBlock(long[] block, long[] state)
        {
            final long[] kw = this.kw;
            final long[] t = this.t;
            final int[] mod17 = MOD17;
            final int[] mod3 = MOD3;

            /* Help the JIT avoid index bounds checks */
            if (kw.length != 33)
            {
                throw new IllegalArgumentException();
            }
            if (t.length != 5)
            {
                throw new IllegalArgumentException();
            }

            long b0 = block[0];
            long b1 = block[1];
            long b2 = block[2];
            long b3 = block[3];
            long b4 = block[4];
            long b5 = block[5];
            long b6 = block[6];
            long b7 = block[7];
            long b8 = block[8];
            long b9 = block[9];
            long b10 = block[10];
            long b11 = block[11];
            long b12 = block[12];
            long b13 = block[13];
            long b14 = block[14];
            long b15 = block[15];

            for (int d = (ROUNDS_1024 / 4) - 1; d >= 1; d -= 2)
            {
                final int dm17 = mod17[d];
                final int dm3 = mod3[d];

                /* Reverse key injection for second 4 rounds */
                b0 -= kw[dm17 + 1];
                b1 -= kw[dm17 + 2];
                b2 -= kw[dm17 + 3];
                b3 -= kw[dm17 + 4];
                b4 -= kw[dm17 + 5];
                b5 -= kw[dm17 + 6];
                b6 -= kw[dm17 + 7];
                b7 -= kw[dm17 + 8];
                b8 -= kw[dm17 + 9];
                b9 -= kw[dm17 + 10];
                b10 -= kw[dm17 + 11];
                b11 -= kw[dm17 + 12];
                b12 -= kw[dm17 + 13];
                b13 -= kw[dm17 + 14] + t[dm3 + 1];
                b14 -= kw[dm17 + 15] + t[dm3 + 2];
                b15 -= kw[dm17 + 16] + d + 1;

                /* Reverse second 4 mix/permute rounds */
                b15 = xorRotr(b15, ROTATION_7_0, b0);
                b0 -= b15;
                b11 = xorRotr(b11, ROTATION_7_1, b2);
                b2 -= b11;
                b13 = xorRotr(b13, ROTATION_7_2, b6);
                b6 -= b13;
                b9 = xorRotr(b9, ROTATION_7_3, b4);
                b4 -= b9;
                b1 = xorRotr(b1, ROTATION_7_4, b14);
                b14 -= b1;
                b5 = xorRotr(b5, ROTATION_7_5, b8);
                b8 -= b5;
                b3 = xorRotr(b3, ROTATION_7_6, b10);
                b10 -= b3;
                b7 = xorRotr(b7, ROTATION_7_7, b12);
                b12 -= b7;

                b7 = xorRotr(b7, ROTATION_6_0, b0);
                b0 -= b7;
                b5 = xorRotr(b5, ROTATION_6_1, b2);
                b2 -= b5;
                b3 = xorRotr(b3, ROTATION_6_2, b4);
                b4 -= b3;
                b1 = xorRotr(b1, ROTATION_6_3, b6);
                b6 -= b1;
                b15 = xorRotr(b15, ROTATION_6_4, b12);
                b12 -= b15;
                b13 = xorRotr(b13, ROTATION_6_5, b14);
                b14 -= b13;
                b11 = xorRotr(b11, ROTATION_6_6, b8);
                b8 -= b11;
                b9 = xorRotr(b9, ROTATION_6_7, b10);
                b10 -= b9;

                b9 = xorRotr(b9, ROTATION_5_0, b0);
                b0 -= b9;
                b13 = xorRotr(b13, ROTATION_5_1, b2);
                b2 -= b13;
                b11 = xorRotr(b11, ROTATION_5_2, b6);
                b6 -= b11;
                b15 = xorRotr(b15, ROTATION_5_3, b4);
                b4 -= b15;
                b7 = xorRotr(b7, ROTATION_5_4, b10);
                b10 -= b7;
                b3 = xorRotr(b3, ROTATION_5_5, b12);
                b12 -= b3;
                b5 = xorRotr(b5, ROTATION_5_6, b14);
                b14 -= b5;
                b1 = xorRotr(b1, ROTATION_5_7, b8);
                b8 -= b1;

                b1 = xorRotr(b1, ROTATION_4_0, b0);
                b0 -= b1;
                b3 = xorRotr(b3, ROTATION_4_1, b2);
                b2 -= b3;
                b5 = xorRotr(b5, ROTATION_4_2, b4);
                b4 -= b5;
                b7 = xorRotr(b7, ROTATION_4_3, b6);
                b6 -= b7;
                b9 = xorRotr(b9, ROTATION_4_4, b8);
                b8 -= b9;
                b11 = xorRotr(b11, ROTATION_4_5, b10);
                b10 -= b11;
                b13 = xorRotr(b13, ROTATION_4_6, b12);
                b12 -= b13;
                b15 = xorRotr(b15, ROTATION_4_7, b14);
                b14 -= b15;

                /* Reverse key injection for first 4 rounds */
                b0 -= kw[dm17];
                b1 -= kw[dm17 + 1];
                b2 -= kw[dm17 + 2];
                b3 -= kw[dm17 + 3];
                b4 -= kw[dm17 + 4];
                b5 -= kw[dm17 + 5];
                b6 -= kw[dm17 + 6];
                b7 -= kw[dm17 + 7];
                b8 -= kw[dm17 + 8];
                b9 -= kw[dm17 + 9];
                b10 -= kw[dm17 + 10];
                b11 -= kw[dm17 + 11];
                b12 -= kw[dm17 + 12];
                b13 -= kw[dm17 + 13] + t[dm3];
                b14 -= kw[dm17 + 14] + t[dm3 + 1];
                b15 -= kw[dm17 + 15] + d;

                /* Reverse first 4 mix/permute rounds */
                b15 = xorRotr(b15, ROTATION_3_0, b0);
                b0 -= b15;
                b11 = xorRotr(b11, ROTATION_3_1, b2);
                b2 -= b11;
                b13 = xorRotr(b13, ROTATION_3_2, b6);
                b6 -= b13;
                b9 = xorRotr(b9, ROTATION_3_3, b4);
                b4 -= b9;
                b1 = xorRotr(b1, ROTATION_3_4, b14);
                b14 -= b1;
                b5 = xorRotr(b5, ROTATION_3_5, b8);
                b8 -= b5;
                b3 = xorRotr(b3, ROTATION_3_6, b10);
                b10 -= b3;
                b7 = xorRotr(b7, ROTATION_3_7, b12);
                b12 -= b7;

                b7 = xorRotr(b7, ROTATION_2_0, b0);
                b0 -= b7;
                b5 = xorRotr(b5, ROTATION_2_1, b2);
                b2 -= b5;
                b3 = xorRotr(b3, ROTATION_2_2, b4);
                b4 -= b3;
                b1 = xorRotr(b1, ROTATION_2_3, b6);
                b6 -= b1;
                b15 = xorRotr(b15, ROTATION_2_4, b12);
                b12 -= b15;
                b13 = xorRotr(b13, ROTATION_2_5, b14);
                b14 -= b13;
                b11 = xorRotr(b11, ROTATION_2_6, b8);
                b8 -= b11;
                b9 = xorRotr(b9, ROTATION_2_7, b10);
                b10 -= b9;

                b9 = xorRotr(b9, ROTATION_1_0, b0);
                b0 -= b9;
                b13 = xorRotr(b13, ROTATION_1_1, b2);
                b2 -= b13;
                b11 = xorRotr(b11, ROTATION_1_2, b6);
                b6 -= b11;
                b15 = xorRotr(b15, ROTATION_1_3, b4);
                b4 -= b15;
                b7 = xorRotr(b7, ROTATION_1_4, b10);
                b10 -= b7;
                b3 = xorRotr(b3, ROTATION_1_5, b12);
                b12 -= b3;
                b5 = xorRotr(b5, ROTATION_1_6, b14);
                b14 -= b5;
                b1 = xorRotr(b1, ROTATION_1_7, b8);
                b8 -= b1;

                b1 = xorRotr(b1, ROTATION_0_0, b0);
                b0 -= b1;
                b3 = xorRotr(b3, ROTATION_0_1, b2);
                b2 -= b3;
                b5 = xorRotr(b5, ROTATION_0_2, b4);
                b4 -= b5;
                b7 = xorRotr(b7, ROTATION_0_3, b6);
                b6 -= b7;
                b9 = xorRotr(b9, ROTATION_0_4, b8);
                b8 -= b9;
                b11 = xorRotr(b11, ROTATION_0_5, b10);
                b10 -= b11;
                b13 = xorRotr(b13, ROTATION_0_6, b12);
                b12 -= b13;
                b15 = xorRotr(b15, ROTATION_0_7, b14);
                b14 -= b15;
            }

            /*
             * First subkey uninjection.
             */
            b0 -= kw[0];
            b1 -= kw[1];
            b2 -= kw[2];
            b3 -= kw[3];
            b4 -= kw[4];
            b5 -= kw[5];
            b6 -= kw[6];
            b7 -= kw[7];
            b8 -= kw[8];
            b9 -= kw[9];
            b10 -= kw[10];
            b11 -= kw[11];
            b12 -= kw[12];
            b13 -= kw[13] + t[0];
            b14 -= kw[14] + t[1];
            b15 -= kw[15];

            /*
             * Output cipher state.
             */
            state[0] = b0;
            state[1] = b1;
            state[2] = b2;
            state[3] = b3;
            state[4] = b4;
            state[5] = b5;
            state[6] = b6;
            state[7] = b7;
            state[8] = b8;
            state[9] = b9;
            state[10] = b10;
            state[11] = b11;
            state[12] = b12;
            state[13] = b13;
            state[14] = b14;
            state[15] = b15;
        }

    }

}
