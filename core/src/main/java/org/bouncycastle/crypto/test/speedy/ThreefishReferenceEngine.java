package org.bouncycastle.crypto.test.speedy;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;

public class ThreefishReferenceEngine
    implements BlockCipher
{

    /**
     * The tweak input is always 128 bits
     */
    private static final int TWEAK_SIZE = 16;

    private static long C_240 = 0x1BD11BDAA9FC1A22L;

    private final int blocksize = 64;
    private final int rounds = 72;
    private final int words = 8;

    private boolean forEncryption;

    private long[] block = new long[words];

    private int[][] rotations = R8;

    /**
     * Rotation constants Rd,j for Nw = 8.
     */
    private static final int[][] R8 = {
        {46, 36, 19, 37},
        {33, 27, 14, 42},
        {17, 49, 36, 39},
        {44, 9, 54, 56},
        {39, 30, 34, 24},
        {13, 50, 10, 17},
        {25, 29, 39, 43},
        {8, 35, 56, 22}};

    private long[] t;

    private long kw[];

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof TweakableBlockCipherParameters)
        {
            init(forEncryption, (TweakableBlockCipherParameters)params);
        }
        else if (params instanceof KeyParameter)
        {
            init(forEncryption, new TweakableBlockCipherParameters((KeyParameter)params, new byte[TWEAK_SIZE]));
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameter passed to Threefish init - "
                + params.getClass().getName());
        }
    }

    public void init(boolean forEncryption, TweakableBlockCipherParameters params)
        throws IllegalArgumentException
    {
        // TODO: Remove some of the NPEs that can be avoided in the Params
        // classes
        if ((params.getKey() == null) || (params.getKey().getKey() == null)
            || (params.getKey().getKey().length != blocksize))
        {
            throw new IllegalArgumentException("Threefish key must be same size as block (%d bytes)" + blocksize);
        }

        if ((params.getTweak() == null) || (params.getTweak().length != TWEAK_SIZE))
        {
            throw new IllegalArgumentException("Threefish tweak must be %d bytes" + TWEAK_SIZE);
        }

        this.forEncryption = forEncryption;

        generateKeySchedule(params.getKey().getKey(), params.getTweak());
    }

    private void generateKeySchedule(byte[] key, byte[] tweak)
    {
        // TODO: This key schedule can/should be generated incrementally/on demand during encrypt/decrypt
        // to reduce memory overhead (currently 1.2MB = (rounds/4+1)=19 * words=8 * 8 bytes/word)

        t = new long[3];
        t[0] = BytesToWord(tweak, 0);
        t[1] = BytesToWord(tweak, 8);
        t[2] = t[0] ^ t[1];

        kw = new long[words + 1];

        long knw = C_240;
        for (int i = 0; i < words; i++)
        {
            kw[i] = BytesToWord(key, i * 8);
            knw = knw ^ kw[i];
        }
        kw[kw.length - 1] = knw;
    }

    private static long BytesToWord(byte[] bytes, int off)
    {
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

    private static void WordToBytes(long word, byte[] bytes, int off)
    {
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

    public String getAlgorithmName()
    {
        return "Threefish";
    }

    public int getBlockSize()
    {
        return blocksize;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException,
        IllegalStateException
    {
        // TODO: Check init state
        if (kw == null)
        {
            throw new IllegalStateException("Threefish engine not initialised");
        }

        if ((inOff + blocksize) > in.length)
        {
            throw new DataLengthException("Input buffer too short");
        }

        if ((outOff + blocksize) > out.length)
        {
            throw new DataLengthException("Output buffer too short");
        }

        if (forEncryption)
        {
            unpackBlock(in, inOff);
            encryptBlock();
            packBlock(out, outOff);
        }
        else
        {
            unpackBlock(in, inOff);
            decryptBlock();
            packBlock(out, outOff);
        }

        return blocksize;
    }

    private void decryptBlock()
    {
        for (int d = rounds; d > 0; d--)
        {
            // Add subkey every 4 rounds
            if ((d % 4) == 0)
            {
                uninjectSubkey(d / 4);
            }

            // Permute
            unpermute();

            // Mix
            for (int j = 0; j < words / 2; j++)
            {
                unmix(j, d - 1);
            }
        }

        // Remove first subkey
        uninjectSubkey(0);
    }

    private void injectSubkey(int s)
    {
        for (int i = 0; i < (words - 3); i++)
        {
            block[i] += kw[(s + i) % (words + 1)];
        }
        block[words - 3] += kw[(s + words - 3) % (words + 1)] + t[s % 3];
        block[words - 2] += kw[(s + words - 2) % (words + 1)] + t[(s + 1) % 3];
        block[words - 1] += kw[(s + words - 1) % (words + 1)] + s;
    }

    private void uninjectSubkey(int s)
    {
        for (int i = 0; i < (words - 3); i++)
        {
            block[i] -= kw[(s + i) % (words + 1)];
        }
        block[words - 3] -= kw[(s + words - 3) % (words + 1)] + t[s % 3];
        block[words - 2] -= kw[(s + words - 2) % (words + 1)] + t[(s + 1) % 3];
        block[words - 1] -= kw[(s + words - 1) % (words + 1)] + s;
    }

    private void encryptBlock()
    {
        for (int d = 0; d < rounds; d++)
        {
            // Add subkey every 4 rounds
            if ((d % 4) == 0)
            {
                injectSubkey(d / 4);
            }

            // Mix
            for (int j = 0; j < words / 2; j++)
            {
                mix(j, d);
            }

            // Permute
            permute();
        }

        // Final key addition
        injectSubkey(rounds / 4);
    }

    private void permute()
    {
        // Permute in place for Nw = 8
        long f0 = block[0];
        long f3 = block[3];

        block[0] = block[2];
        block[1] = block[1];
        block[2] = block[4];
        block[3] = block[7];
        block[4] = block[6];
        block[5] = block[5];
        block[6] = f0;
        block[7] = f3;
    }

    private void unpermute()
    {
        // TODO: Change these to tables
        // Permute in place for Nw = 8
        long f6 = block[6];
        long f7 = block[7];

        block[7] = block[3];
        block[6] = block[4];
        block[5] = block[5];
        block[4] = block[2];
        block[3] = f7;
        block[2] = block[0];
        block[1] = block[1];
        block[0] = f6;
    }

    private void mix(int j, int d)
    {
        // ed,2j and ed,2j+1
        int b0 = 2 * j;
        int b1 = b0 + 1;

        // y0 = x0 + x1
        block[b0] = block[b0] + block[b1];

        // y1 = (x1 <<< R(d mod 8,j)) xor y0
        block[b1] = Long.rotateLeft(block[b1], rotations[d % 8][j]) ^ block[b0];
    }

    private void unmix(int j, int d)
    {
        // ed,2j and ed,2j+1
        int b0 = 2 * j;
        int b1 = b0 + 1;

        // x1 = (y1 ^ y0) >>> R(d mod 8, j))
        block[b1] = Long.rotateRight(block[b1] ^ block[b0], rotations[d % 8][j]);

        // x0 = y0 - x1
        block[b0] = block[b0] - block[b1];

    }

    public static void main(String[] args)
    {
        ThreefishReferenceEngine engine = new ThreefishReferenceEngine();
        engine.fu();
    }

    private void fu()
    {
        block[0] = 0x12;
        block[1] = 0x34;
        block[2] = 0x56;
        block[3] = 0x78;
        block[4] = 0x90;
        block[5] = 0xAB;
        block[6] = 0xCD;
        block[7] = 0xEF;

        for (int i = 0; i < block.length; i++)
        {
            System.err.println(i + " : " + Long.toHexString(block[i]));
        }
        mix(0, 4);
        System.err.println("=========");
        for (int i = 0; i < block.length; i++)
        {
            System.err.println(i + " : " + Long.toHexString(block[i]));
        }
        unmix(0, 4);
        System.err.println("=========");
        for (int i = 0; i < block.length; i++)
        {
            System.err.println(i + " : " + Long.toHexString(block[i]));
        }
        permute();
        System.err.println("=========");
        for (int i = 0; i < block.length; i++)
        {
            System.err.println(i + " : " + Long.toHexString(block[i]));
        }
        unpermute();
        System.err.println("=========");
        for (int i = 0; i < block.length; i++)
        {
            System.err.println(i + " : " + Long.toHexString(block[i]));
        }
        generateKeySchedule(new byte[blocksize], new byte[TWEAK_SIZE]);
        injectSubkey(5);
        System.err.println("=========");
        for (int i = 0; i < block.length; i++)
        {
            System.err.println(i + " : " + Long.toHexString(block[i]));
        }
        uninjectSubkey(5);
        System.err.println("=========");
        for (int i = 0; i < block.length; i++)
        {
            System.err.println(i + " : " + Long.toHexString(block[i]));
        }
    }

    private void packBlock(byte[] out, int outOff)
    {
        for (int i = 0; i < block.length; i++)
        {
            WordToBytes(block[i], out, outOff + (i * 8));
        }
    }

    private long[] unpackBlock(byte[] bytes, int index)
    {
        for (int i = 0; i < block.length; i++)
        {
            block[i] = BytesToWord(bytes, index + (i * 8));
        }
        return block;
    }

    public void reset()
    {
    }

}
