package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RC5Parameters;

/**
 * The specification for RC5 came from the <code>RC5 Encryption Algorithm</code>
 * publication in RSA CryptoBytes, Spring of 1995. 
 * <em>http://www.rsasecurity.com/rsalabs/cryptobytes</em>.
 * <p>
 * This implementation has a word size of 32 bits.
 * <p>
 * Implementation courtesy of Tito Pena.
 */
public class RC532Engine
    implements BlockCipher
{
    /*
     * the number of rounds to perform
     */
    private int _noRounds;

    /*
     * the expanded key array of size 2*(rounds + 1)
     */
    private int _S[];

    /*
     * our "magic constants" for 32 32
     *
     * Pw = Odd((e-2) * 2^wordsize)
     * Qw = Odd((o-2) * 2^wordsize)
     *
     * where e is the base of natural logarithms (2.718281828...)
     * and o is the golden ratio (1.61803398...)
     */
    private static final int P32 = 0xb7e15163;
    private static final int Q32 = 0x9e3779b9;

    private boolean forEncryption;

    /**
     * Create an instance of the RC5 encryption algorithm
     * and set some defaults
     */
    public RC532Engine()
    {
        _noRounds     = 12;         // the default
        _S            = null;
    }

    public String getAlgorithmName()
    {
        return "RC5-32";
    }

    public int getBlockSize()
    {
        return 2 * 4;
    }

    /**
     * initialise a RC5-32 cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             forEncryption,
        CipherParameters    params)
    {
        if (params instanceof RC5Parameters)
        {
            RC5Parameters       p = (RC5Parameters)params;

            _noRounds     = p.getRounds();

            setKey(p.getKey());
        }
        else if (params instanceof KeyParameter)
        {
            KeyParameter       p = (KeyParameter)params;

            setKey(p.getKey());
        }
        else
        {
            throw new IllegalArgumentException("invalid parameter passed to RC532 init - " + params.getClass().getName());
        }

        this.forEncryption = forEncryption;
    }

    public int processBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        return (forEncryption) ? encryptBlock(in, inOff, out, outOff) 
                                    : decryptBlock(in, inOff, out, outOff);
    }

    public void reset()
    {
    }

    /**
     * Re-key the cipher.
     * <p>
     * @param  key  the key to be used
     */
    private void setKey(
        byte[]      key)
    {
        //
        // KEY EXPANSION:
        //
        // There are 3 phases to the key expansion.
        //
        // Phase 1:
        //   Copy the secret key K[0...b-1] into an array L[0..c-1] of
        //   c = ceil(b/u), where u = 32/8 in little-endian order.
        //   In other words, we fill up L using u consecutive key bytes
        //   of K. Any unfilled byte positions in L are zeroed. In the
        //   case that b = c = 0, set c = 1 and L[0] = 0.
        //
        int[]   L = new int[(key.length + (4 - 1)) / 4];

        for (int i = 0; i != key.length; i++)
        {
            L[i / 4] += (key[i] & 0xff) << (8 * (i % 4));
        }

        //
        // Phase 2:
        //   Initialize S to a particular fixed pseudo-random bit pattern
        //   using an arithmetic progression modulo 2^wordsize determined
        //   by the magic numbers, Pw & Qw.
        //
        _S            = new int[2*(_noRounds + 1)];

        _S[0] = P32;
        for (int i=1; i < _S.length; i++)
        {
            _S[i] = (_S[i-1] + Q32);
        }

        //
        // Phase 3:
        //   Mix in the user's secret key in 3 passes over the arrays S & L.
        //   The max of the arrays sizes is used as the loop control
        //
        int iter;

        if (L.length > _S.length)
        {
            iter = 3 * L.length;
        }
        else
        {
            iter = 3 * _S.length;
        }

        int A = 0, B = 0;
        int i = 0, j = 0;

        for (int k = 0; k < iter; k++)
        {
            A = _S[i] = rotateLeft(_S[i] + A + B, 3);
            B =  L[j] = rotateLeft(L[j] + A + B, A+B);
            i = (i+1) % _S.length;
            j = (j+1) %  L.length;
        }
    }

    /**
     * Encrypt the given block starting at the given offset and place
     * the result in the provided buffer starting at the given offset.
     * <p>
     * @param  in     in byte buffer containing data to encrypt
     * @param  inOff  offset into src buffer
     * @param  out     out buffer where encrypted data is written
     * @param  outOff  offset into out buffer
     */
    private int encryptBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        int A = bytesToWord(in, inOff) + _S[0];
        int B = bytesToWord(in, inOff + 4) + _S[1];

        for (int i = 1; i <= _noRounds; i++)
        {
            A = rotateLeft(A ^ B, B) + _S[2*i];
            B = rotateLeft(B ^ A, A) + _S[2*i+1];
        }
        
        wordToBytes(A, out, outOff);
        wordToBytes(B, out, outOff + 4);
        
        return 2 * 4;
    }

    private int decryptBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        int A = bytesToWord(in, inOff);
        int B = bytesToWord(in, inOff + 4);

        for (int i = _noRounds; i >= 1; i--)
        {
            B = rotateRight(B - _S[2*i+1], A) ^ A;
            A = rotateRight(A - _S[2*i],   B) ^ B;
        }
        
        wordToBytes(A - _S[0], out, outOff);
        wordToBytes(B - _S[1], out, outOff + 4);
        
        return 2 * 4;
    }

    
    //////////////////////////////////////////////////////////////
    //
    // PRIVATE Helper Methods
    //
    //////////////////////////////////////////////////////////////

    /**
     * Perform a left "spin" of the word. The rotation of the given
     * word <em>x</em> is rotated left by <em>y</em> bits.
     * Only the <em>lg(32)</em> low-order bits of <em>y</em>
     * are used to determine the rotation amount. Here it is 
     * assumed that the wordsize used is a power of 2.
     * <p>
     * @param  x  word to rotate
     * @param  y    number of bits to rotate % 32
     */
    private int rotateLeft(int x, int y)
    {
        return ((x << (y & (32-1))) | (x >>> (32 - (y & (32-1)))));
    }

    /**
     * Perform a right "spin" of the word. The rotation of the given
     * word <em>x</em> is rotated left by <em>y</em> bits.
     * Only the <em>lg(32)</em> low-order bits of <em>y</em>
     * are used to determine the rotation amount. Here it is 
     * assumed that the wordsize used is a power of 2.
     * <p>
     * @param  x  word to rotate
     * @param  y    number of bits to rotate % 32
     */
    private int rotateRight(int x, int y)
    {
        return ((x >>> (y & (32-1))) | (x << (32 - (y & (32-1)))));
    }

    private int bytesToWord(
        byte[]  src,
        int     srcOff)
    {
        return (src[srcOff] & 0xff) | ((src[srcOff + 1] & 0xff) << 8)
            | ((src[srcOff + 2] & 0xff) << 16) | ((src[srcOff + 3] & 0xff) << 24);
    }

    private void wordToBytes(
        int    word,
        byte[]  dst,
        int     dstOff)
    {
        dst[dstOff] = (byte)word;
        dst[dstOff + 1] = (byte)(word >> 8);
        dst[dstOff + 2] = (byte)(word >> 16);
        dst[dstOff + 3] = (byte)(word >> 24);
    }
}
