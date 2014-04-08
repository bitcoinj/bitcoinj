package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;


/**
 * Implementation of WhirlpoolDigest, based on Java source published by Barreto
 * and Rijmen.
 *  
 */
public final class WhirlpoolDigest 
    implements ExtendedDigest, Memoable
{
    private static final int BYTE_LENGTH = 64;
    
    private static final int DIGEST_LENGTH_BYTES = 512 / 8;
    private static final int ROUNDS = 10;
    private static final int REDUCTION_POLYNOMIAL = 0x011d; // 2^8 + 2^4 + 2^3 + 2 + 1;

    private static final int[] SBOX = {
        0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
        0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
        0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
        0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
        0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
        0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
        0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
        0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
        0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
        0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
        0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
        0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
        0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
        0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
        0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
        0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
    };
    
    private static final long[] C0 = new long[256];
    private static final long[] C1 = new long[256];
    private static final long[] C2 = new long[256];
    private static final long[] C3 = new long[256];
    private static final long[] C4 = new long[256];
    private static final long[] C5 = new long[256];
    private static final long[] C6 = new long[256];
    private static final long[] C7 = new long[256];

    private final long[] _rc = new long[ROUNDS + 1];
        
    public WhirlpoolDigest()
    {
        for (int i = 0; i < 256; i++)
        {
            int v1 = SBOX[i];
            int v2 = maskWithReductionPolynomial(v1 << 1);
            int v4 = maskWithReductionPolynomial(v2 << 1);
            int v5 = v4 ^ v1;
            int v8 = maskWithReductionPolynomial(v4 << 1);
            int v9 = v8 ^ v1;
            
            C0[i] = packIntoLong(v1, v1, v4, v1, v8, v5, v2, v9);
            C1[i] = packIntoLong(v9, v1, v1, v4, v1, v8, v5, v2);
            C2[i] = packIntoLong(v2, v9, v1, v1, v4, v1, v8, v5);
            C3[i] = packIntoLong(v5, v2, v9, v1, v1, v4, v1, v8);
            C4[i] = packIntoLong(v8, v5, v2, v9, v1, v1, v4, v1);
            C5[i] = packIntoLong(v1, v8, v5, v2, v9, v1, v1, v4);
            C6[i] = packIntoLong(v4, v1, v8, v5, v2, v9, v1, v1);
            C7[i] = packIntoLong(v1, v4, v1, v8, v5, v2, v9, v1);
            
        }
        
        _rc[0] = 0L;
        for (int r = 1; r <= ROUNDS; r++)
        {
            int i = 8 * (r - 1);
            _rc[r] =    (C0[i    ] & 0xff00000000000000L) ^ 
                        (C1[i + 1] & 0x00ff000000000000L) ^ 
                        (C2[i + 2] & 0x0000ff0000000000L) ^
                        (C3[i + 3] & 0x000000ff00000000L) ^ 
                        (C4[i + 4] & 0x00000000ff000000L) ^
                        (C5[i + 5] & 0x0000000000ff0000L) ^
                        (C6[i + 6] & 0x000000000000ff00L) ^ 
                        (C7[i + 7] & 0x00000000000000ffL);
        }
        
    }

    private long packIntoLong(int b7, int b6, int b5, int b4, int b3, int b2, int b1, int b0)
    {
        return 
                    ((long)b7 << 56) ^
                    ((long)b6 << 48) ^
                    ((long)b5 << 40) ^
                    ((long)b4 << 32) ^
                    ((long)b3 << 24) ^
                    ((long)b2 << 16) ^
                    ((long)b1 <<  8) ^
                    b0;
    }

    /*
     * int's are used to prevent sign extension.  The values that are really being used are
     * actually just 0..255
     */
    private int maskWithReductionPolynomial(int input)
    {
        int rv = input;
        if (rv >= 0x100L) // high bit set
        {
            rv ^= REDUCTION_POLYNOMIAL; // reduced by the polynomial
        }
        return rv;
    }
        
    // --------------------------------------------------------------------------------------//
    
    // -- buffer information --
    private static final int BITCOUNT_ARRAY_SIZE = 32;
    private byte[]  _buffer    = new byte[64];
    private int     _bufferPos = 0;
    private short[] _bitCount  = new short[BITCOUNT_ARRAY_SIZE];
    
    // -- internal hash state --
    private long[] _hash  = new long[8];
    private long[] _K = new long[8]; // the round key
    private long[] _L = new long[8];
    private long[] _block = new long[8]; // mu (buffer)
    private long[] _state = new long[8]; // the current "cipher" state
    


    /**
     * Copy constructor. This will copy the state of the provided message
     * digest.
     */
    public WhirlpoolDigest(WhirlpoolDigest originalDigest)
    {
        reset(originalDigest);
    }

    public String getAlgorithmName()
    {
        return "Whirlpool";
    }

    public int getDigestSize()
    {
        return DIGEST_LENGTH_BYTES;
    }

    public int doFinal(byte[] out, int outOff)
    {
        // sets out[outOff] .. out[outOff+DIGEST_LENGTH_BYTES]
        finish();

        for (int i = 0; i < 8; i++)
        {
            convertLongToByteArray(_hash[i], out, outOff + (i * 8));
        }

        reset();        
        return getDigestSize();
    }
    
    /**
     * reset the chaining variables
     */
    public void reset()
    {
        // set variables to null, blank, whatever
        _bufferPos = 0;
        Arrays.fill(_bitCount, (short)0);
        Arrays.fill(_buffer, (byte)0);
        Arrays.fill(_hash, 0);
        Arrays.fill(_K, 0);
        Arrays.fill(_L, 0);
        Arrays.fill(_block, 0);
        Arrays.fill(_state, 0);
    }

    // this takes a buffer of information and fills the block
    private void processFilledBuffer(byte[] in, int inOff)
    {
        // copies into the block...
        for (int i = 0; i < _state.length; i++)
        {
            _block[i] = bytesToLongFromBuffer(_buffer, i * 8);
        }
        processBlock();
        _bufferPos = 0;
        Arrays.fill(_buffer, (byte)0);
    }

    private long bytesToLongFromBuffer(byte[] buffer, int startPos)
    {
        long rv = (((buffer[startPos + 0] & 0xffL) << 56) |
                   ((buffer[startPos + 1] & 0xffL) << 48) |
                   ((buffer[startPos + 2] & 0xffL) << 40) |
                   ((buffer[startPos + 3] & 0xffL) << 32) |
                   ((buffer[startPos + 4] & 0xffL) << 24) |
                   ((buffer[startPos + 5] & 0xffL) << 16) |
                   ((buffer[startPos + 6] & 0xffL) <<  8) |
                   ((buffer[startPos + 7]) & 0xffL));
        
        return rv;
    }

    private void convertLongToByteArray(long inputLong, byte[] outputArray, int offSet)
    {
        for (int i = 0; i < 8; i++)
        {
            outputArray[offSet + i] = (byte)((inputLong >> (56 - (i * 8))) & 0xff);
        }
    }

    protected void processBlock()
    {
        // buffer contents have been transferred to the _block[] array via
        // processFilledBuffer
        
        // compute and apply K^0
        for (int i = 0; i < 8; i++)
        {
            _state[i] = _block[i] ^ (_K[i] = _hash[i]);
        }

        // iterate over the rounds
        for (int round = 1; round <= ROUNDS; round++)
        {
            for (int i = 0; i < 8; i++)
            {
                _L[i] = 0;
                _L[i] ^= C0[(int)(_K[(i - 0) & 7] >>> 56) & 0xff];
                _L[i] ^= C1[(int)(_K[(i - 1) & 7] >>> 48) & 0xff];
                _L[i] ^= C2[(int)(_K[(i - 2) & 7] >>> 40) & 0xff];
                _L[i] ^= C3[(int)(_K[(i - 3) & 7] >>> 32) & 0xff];
                _L[i] ^= C4[(int)(_K[(i - 4) & 7] >>> 24) & 0xff];
                _L[i] ^= C5[(int)(_K[(i - 5) & 7] >>> 16) & 0xff];
                _L[i] ^= C6[(int)(_K[(i - 6) & 7] >>>  8) & 0xff];
                _L[i] ^= C7[(int)(_K[(i - 7) & 7]) & 0xff];
            }

            System.arraycopy(_L, 0, _K, 0, _K.length);
            
            _K[0] ^= _rc[round];
            
            // apply the round transformation
            for (int i = 0; i < 8; i++)
            {
                _L[i] = _K[i];
                
                _L[i] ^= C0[(int)(_state[(i - 0) & 7] >>> 56) & 0xff];
                _L[i] ^= C1[(int)(_state[(i - 1) & 7] >>> 48) & 0xff];
                _L[i] ^= C2[(int)(_state[(i - 2) & 7] >>> 40) & 0xff];
                _L[i] ^= C3[(int)(_state[(i - 3) & 7] >>> 32) & 0xff];
                _L[i] ^= C4[(int)(_state[(i - 4) & 7] >>> 24) & 0xff];
                _L[i] ^= C5[(int)(_state[(i - 5) & 7] >>> 16) & 0xff];
                _L[i] ^= C6[(int)(_state[(i - 6) & 7] >>> 8) & 0xff];
                _L[i] ^= C7[(int)(_state[(i - 7) & 7]) & 0xff];
            }
            
            // save the current state
            System.arraycopy(_L, 0, _state, 0, _state.length);
        }
        
        // apply Miuaguchi-Preneel compression
        for (int i = 0; i < 8; i++)
        {
            _hash[i] ^= _state[i] ^ _block[i];
        }
        
    }

    public void update(byte in)
    {
        _buffer[_bufferPos] = in;

        //System.out.println("adding to buffer = "+_buffer[_bufferPos]);
        
        ++_bufferPos;
        
        if (_bufferPos == _buffer.length)
        {
            processFilledBuffer(_buffer, 0);
        }

        increment();
    }

    /*
     * increment() can be implemented in this way using 2 arrays or
     * by having some temporary variables that are used to set the
     * value provided by EIGHT[i] and carry within the loop.
     * 
     * not having done any timing, this seems likely to be faster
     * at the slight expense of 32*(sizeof short) bytes
     */
    private static final short[] EIGHT = new short[BITCOUNT_ARRAY_SIZE];
    static 
    {
        EIGHT[BITCOUNT_ARRAY_SIZE - 1] = 8;
    }
    
    private void increment()
    {
        int carry = 0;
        for (int i = _bitCount.length - 1; i >= 0; i--)
        {
            int sum = (_bitCount[i] & 0xff) + EIGHT[i] + carry;

            carry = sum >>> 8;
            _bitCount[i] = (short)(sum & 0xff);
        }
    }    
    
    public void update(byte[] in, int inOff, int len)
    {
        while (len > 0)
        {
            update(in[inOff]);
            ++inOff;
            --len;
        }
        
    }
    
    private void finish()
    {
        /*
         * this makes a copy of the current bit length. at the expense of an
         * object creation of 32 bytes rather than providing a _stopCounting
         * boolean which was the alternative I could think of.
         */
        byte[] bitLength = copyBitLength(); 
        
        _buffer[_bufferPos++] |= 0x80;

        if (_bufferPos == _buffer.length)
        {
            processFilledBuffer(_buffer, 0);
        }

        /*
         * Final block contains 
         * [ ... data .... ][0][0][0][ length ]
         * 
         * if [ length ] cannot fit.  Need to create a new block.
         */
        if (_bufferPos > 32)
        {
            while (_bufferPos != 0)
            {
                update((byte)0);
            }
        }
        
        while (_bufferPos <= 32)
        {
            update((byte)0);
        }
        
        // copy the length information to the final 32 bytes of the
        // 64 byte block....
        System.arraycopy(bitLength, 0, _buffer, 32, bitLength.length);
        
        processFilledBuffer(_buffer, 0);
    }

    private byte[] copyBitLength()
    {
        byte[] rv = new byte[BITCOUNT_ARRAY_SIZE];
        for (int i = 0; i < rv.length; i++)
        {
            rv[i] = (byte)(_bitCount[i] & 0xff);
        }
        return rv;
    }    
    
    public int getByteLength()
    {
        return BYTE_LENGTH;
    }

    public Memoable copy()
    {
        return new WhirlpoolDigest(this);
    }

    public void reset(Memoable other)
    {
        WhirlpoolDigest originalDigest = (WhirlpoolDigest)other;

        System.arraycopy(originalDigest._rc, 0, _rc, 0, _rc.length);

        System.arraycopy(originalDigest._buffer, 0, _buffer, 0, _buffer.length);

        this._bufferPos = originalDigest._bufferPos;
        System.arraycopy(originalDigest._bitCount, 0, _bitCount, 0, _bitCount.length);

        // -- internal hash state --
        System.arraycopy(originalDigest._hash, 0, _hash, 0, _hash.length);
        System.arraycopy(originalDigest._K, 0, _K, 0, _K.length);
        System.arraycopy(originalDigest._L, 0, _L, 0, _L.length);
        System.arraycopy(originalDigest._block, 0, _block, 0, _block.length);
        System.arraycopy(originalDigest._state, 0, _state, 0, _state.length);
    }
}
