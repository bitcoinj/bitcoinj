package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * Implementation of Chinese SM3 digest as described at
 * http://tools.ietf.org/html/draft-shen-sm3-hash-00
 * and at .... ( Chinese PDF )
 * <p>
 * The specification says "process a bit stream",
 * but this is written to process bytes in blocks of 4,
 * meaning this will process 32-bit word groups.
 * But so do also most other digest specifications,
 * including the SHA-256 which was a origin for
 * this specification.
 */
public class SM3Digest
    extends GeneralDigest
{
    private static final int DIGEST_LENGTH = 32;   // bytes
    private static final int BLOCK_SIZE = 64 / 4; // of 32 bit ints (16 ints)

    private int[] V = new int[DIGEST_LENGTH / 4]; // in 32 bit ints (8 ints)
    private int[] inwords = new int[BLOCK_SIZE];
    private int xOff;

    // Work-bufs used within processBlock()
    private int[] W = new int[68];
    private int[] W1 = new int[64];

    // Round constant T for processBlock() which is 32 bit integer rolled left up to (63 MOD 32) bit positions.
    private static final int[] T = new int[64];

    static
    {
        for (int i = 0; i < 16; ++i)
        {
            int t = 0x79CC4519;
            T[i] = (t << i) | (t >>> (32 - i));
        }
        for (int i = 16; i < 64; ++i)
        {
            int n = i % 32;
            int t = 0x7A879D8A;
            T[i] = (t << n) | (t >>> (32 - n));
        }
    }


    /**
     * Standard constructor
     */
    public SM3Digest()
    {
        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    public SM3Digest(SM3Digest t)
    {
        super(t);

        copyIn(t);
    }

    private void copyIn(SM3Digest t)
    {
        System.arraycopy(t.V, 0, this.V, 0, this.V.length);
        System.arraycopy(t.inwords, 0, this.inwords, 0, this.inwords.length);
        xOff = t.xOff;
    }

    public String getAlgorithmName()
    {
        return "SM3";
    }

    public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }


    public Memoable copy()
    {
        return new SM3Digest(this);
    }

    public void reset(Memoable other)
    {
        SM3Digest d = (SM3Digest)other;

        super.copyIn(d);
        copyIn(d);
    }


    /**
     * reset the chaining variables
     */
    public void reset()
    {
        super.reset();

        this.V[0] = 0x7380166F;
        this.V[1] = 0x4914B2B9;
        this.V[2] = 0x172442D7;
        this.V[3] = 0xDA8A0600;
        this.V[4] = 0xA96F30BC;
        this.V[5] = 0x163138AA;
        this.V[6] = 0xE38DEE4D;
        this.V[7] = 0xB0FB0E4E;

        this.xOff = 0;
    }


    public int doFinal(byte[] out,
                       int outOff)
    {
        finish();

        Pack.intToBigEndian(this.V[0], out, outOff + 0);
        Pack.intToBigEndian(this.V[1], out, outOff + 4);
        Pack.intToBigEndian(this.V[2], out, outOff + 8);
        Pack.intToBigEndian(this.V[3], out, outOff + 12);
        Pack.intToBigEndian(this.V[4], out, outOff + 16);
        Pack.intToBigEndian(this.V[5], out, outOff + 20);
        Pack.intToBigEndian(this.V[6], out, outOff + 24);
        Pack.intToBigEndian(this.V[7], out, outOff + 28);

        reset();

        return DIGEST_LENGTH;
    }


    protected void processWord(byte[] in,
                               int inOff)
    {
        // Note: Inlined for performance
        // this.inwords[xOff] = Pack.bigEndianToInt(in, inOff);
        int n = (((in[inOff] & 0xff) << 24) |
            ((in[++inOff] & 0xff) << 16) |
            ((in[++inOff] & 0xff) << 8) |
            ((in[++inOff] & 0xff)));

        this.inwords[this.xOff] = n;
        ++this.xOff;

        if (this.xOff >= 16)
        {
            processBlock();
        }
    }

    protected void processLength(long bitLength)
    {
        if (this.xOff > (BLOCK_SIZE - 2))
        {
            // xOff == 15  --> can't fit the 64 bit length field at tail..
            this.inwords[this.xOff] = 0; // fill with zero
            ++this.xOff;

            processBlock();
        }
        // Fill with zero words, until reach 2nd to last slot
        while (this.xOff < (BLOCK_SIZE - 2))
        {
            this.inwords[this.xOff] = 0;
            ++this.xOff;
        }

        // Store input data length in BITS
        this.inwords[this.xOff++] = (int)(bitLength >>> 32);
        this.inwords[this.xOff++] = (int)(bitLength);
    }

/*

3.4.2.  Constants


   Tj = 79cc4519        when 0  < = j < = 15
   Tj = 7a879d8a        when 16 < = j < = 63

3.4.3.  Boolean function


   FFj(X;Y;Z) = X XOR Y XOR Z                       when 0  < = j < = 15
              = (X AND Y) OR (X AND Z) OR (Y AND Z) when 16 < = j < = 63

   GGj(X;Y;Z) = X XOR Y XOR Z                       when 0  < = j < = 15
              = (X AND Y) OR (NOT X AND Z)          when 16 < = j < = 63

   The X, Y, Z in the fomular are words!GBP

3.4.4.  Permutation function


   P0(X) = X XOR (X <<<  9) XOR (X <<< 17)   ## ROLL, not SHIFT
   P1(X) = X XOR (X <<< 15) XOR (X <<< 23)   ## ROLL, not SHIFT

   The X in the fomular are a word.

----------

Each ROLL converted to Java expression:

ROLL 9  :  ((x <<  9) | (x >>> (32-9))))
ROLL 17 :  ((x << 17) | (x >>> (32-17)))
ROLL 15 :  ((x << 15) | (x >>> (32-15)))
ROLL 23 :  ((x << 23) | (x >>> (32-23)))

 */

    private int P0(final int x)
    {
        final int r9 = ((x << 9) | (x >>> (32 - 9)));
        final int r17 = ((x << 17) | (x >>> (32 - 17)));
        return (x ^ r9 ^ r17);
    }

    private int P1(final int x)
    {
        final int r15 = ((x << 15) | (x >>> (32 - 15)));
        final int r23 = ((x << 23) | (x >>> (32 - 23)));
        return (x ^ r15 ^ r23);
    }

    private int FF0(final int x, final int y, final int z)
    {
        return (x ^ y ^ z);
    }

    private int FF1(final int x, final int y, final int z)
    {
        return ((x & y) | (x & z) | (y & z));
    }

    private int GG0(final int x, final int y, final int z)
    {
        return (x ^ y ^ z);
    }

    private int GG1(final int x, final int y, final int z)
    {
        return ((x & y) | ((~x) & z));
    }


    protected void processBlock()
    {
        for (int j = 0; j < 16; ++j)
        {
            this.W[j] = this.inwords[j];
        }
        for (int j = 16; j < 68; ++j)
        {
            int wj3 = this.W[j - 3];
            int r15 = ((wj3 << 15) | (wj3 >>> (32 - 15)));
            int wj13 = this.W[j - 13];
            int r7 = ((wj13 << 7) | (wj13 >>> (32 - 7)));
            this.W[j] = P1(this.W[j - 16] ^ this.W[j - 9] ^ r15) ^ r7 ^ this.W[j - 6];
        }
        for (int j = 0; j < 64; ++j)
        {
            this.W1[j] = this.W[j] ^ this.W[j + 4];
        }

        int A = this.V[0];
        int B = this.V[1];
        int C = this.V[2];
        int D = this.V[3];
        int E = this.V[4];
        int F = this.V[5];
        int G = this.V[6];
        int H = this.V[7];


        for (int j = 0; j < 16; ++j)
        {
            int a12 = ((A << 12) | (A >>> (32 - 12)));
            int s1_ = a12 + E + T[j];
            int SS1 = ((s1_ << 7) | (s1_ >>> (32 - 7)));
            int SS2 = SS1 ^ a12;
            int TT1 = FF0(A, B, C) + D + SS2 + this.W1[j];
            int TT2 = GG0(E, F, G) + H + SS1 + this.W[j];
            D = C;
            C = ((B << 9) | (B >>> (32 - 9)));
            B = A;
            A = TT1;
            H = G;
            G = ((F << 19) | (F >>> (32 - 19)));
            F = E;
            E = P0(TT2);
        }

        // Different FF,GG functions on rounds 16..63
        for (int j = 16; j < 64; ++j)
        {
            int a12 = ((A << 12) | (A >>> (32 - 12)));
            int s1_ = a12 + E + T[j];
            int SS1 = ((s1_ << 7) | (s1_ >>> (32 - 7)));
            int SS2 = SS1 ^ a12;
            int TT1 = FF1(A, B, C) + D + SS2 + this.W1[j];
            int TT2 = GG1(E, F, G) + H + SS1 + this.W[j];
            D = C;
            C = ((B << 9) | (B >>> (32 - 9)));
            B = A;
            A = TT1;
            H = G;
            G = ((F << 19) | (F >>> (32 - 19)));
            F = E;
            E = P0(TT2);
        }

        this.V[0] ^= A;
        this.V[1] ^= B;
        this.V[2] ^= C;
        this.V[3] ^= D;
        this.V[4] ^= E;
        this.V[5] ^= F;
        this.V[6] ^= G;
        this.V[7] ^= H;

        this.xOff = 0;
    }
}
