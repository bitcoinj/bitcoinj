package org.bouncycastle.crypto.engines;


/**
 * A class that provides CAST6 key encryption operations,
 * such as encoding data and generating keys.
 *
 * All the algorithms herein are from the Internet RFC
 *
 * RFC2612 - CAST6 (128bit block, 128-256bit key)
 *
 * and implement a simplified cryptography interface.
 */
public final class CAST6Engine extends CAST5Engine
{
    //====================================
    // Useful constants
    //====================================

    protected static final int    ROUNDS = 12;

    protected static final int    BLOCK_SIZE = 16;  // bytes = 128 bits

    /*
     * Put the round and mask keys into an array.
     * Kr0[i] => _Kr[i*4 + 0]
     */
    protected int _Kr[] = new int[ROUNDS*4]; // the rotating round key(s)
    protected int _Km[] = new int[ROUNDS*4]; // the masking round key(s)

    /*
     * Key setup
     */
    protected int _Tr[] = new int[24 * 8];
    protected int _Tm[] = new int[24 * 8];

    private int[] _workingKey = new int[8];

    public CAST6Engine()
    {
    }

    public String getAlgorithmName()
    {
        return "CAST6";
    }

    public void reset()
    {
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    //==================================
    // Private Implementation
    //==================================

    /*
     * Creates the subkeys using the same nomenclature
     * as described in RFC2612.
     *
     * See section 2.4
     */
    protected void setKey(byte[] key)
    {
        int Cm = 0x5a827999;
        int Mm = 0x6ed9eba1;
        int Cr = 19;
        int Mr = 17;

        /* 
         * Determine the key size here, if required
         *
         * if keysize < 256 bytes, pad with 0
         *
         * Typical key sizes => 128, 160, 192, 224, 256
         */
        for (int i=0; i< 24; i++)
        {
            for (int j=0; j< 8; j++)
            {
                _Tm[i*8 + j] = Cm;
                Cm = (Cm + Mm);    // mod 2^32;

                _Tr[i*8 + j] = Cr;
                Cr = (Cr + Mr) & 0x1f;            // mod 32
            }
        }

        byte[] tmpKey = new byte[64];
        int length = key.length;
        System.arraycopy(key, 0, tmpKey, 0, length);

        // now create ABCDEFGH
        for (int i=0; i< 8; i++)
        {
            _workingKey[i] = BytesTo32bits(tmpKey, i*4);
        }

        // Generate the key schedule
        for (int i=0; i< 12; i++)
        {
            // KAPPA <- W2i(KAPPA)
            int i2 = i*2 *8;
            _workingKey[6] ^= F1(_workingKey[7], _Tm[i2  ], _Tr[i2  ]);
            _workingKey[5] ^= F2(_workingKey[6], _Tm[i2+1], _Tr[i2+1]);
            _workingKey[4] ^= F3(_workingKey[5], _Tm[i2+2], _Tr[i2+2]);
            _workingKey[3] ^= F1(_workingKey[4], _Tm[i2+3], _Tr[i2+3]);
            _workingKey[2] ^= F2(_workingKey[3], _Tm[i2+4], _Tr[i2+4]);
            _workingKey[1] ^= F3(_workingKey[2], _Tm[i2+5], _Tr[i2+5]);
            _workingKey[0] ^= F1(_workingKey[1], _Tm[i2+6], _Tr[i2+6]);
            _workingKey[7] ^= F2(_workingKey[0], _Tm[i2+7], _Tr[i2+7]);

            // KAPPA <- W2i+1(KAPPA)
            i2 = (i*2 + 1)*8;
            _workingKey[6] ^= F1(_workingKey[7], _Tm[i2  ], _Tr[i2  ]);
            _workingKey[5] ^= F2(_workingKey[6], _Tm[i2+1], _Tr[i2+1]);
            _workingKey[4] ^= F3(_workingKey[5], _Tm[i2+2], _Tr[i2+2]);
            _workingKey[3] ^= F1(_workingKey[4], _Tm[i2+3], _Tr[i2+3]);
            _workingKey[2] ^= F2(_workingKey[3], _Tm[i2+4], _Tr[i2+4]);
            _workingKey[1] ^= F3(_workingKey[2], _Tm[i2+5], _Tr[i2+5]);
            _workingKey[0] ^= F1(_workingKey[1], _Tm[i2+6], _Tr[i2+6]);
            _workingKey[7] ^= F2(_workingKey[0], _Tm[i2+7], _Tr[i2+7]);

            // Kr_(i) <- KAPPA
            _Kr[i*4    ] = _workingKey[0] & 0x1f;
            _Kr[i*4 + 1] = _workingKey[2] & 0x1f;
            _Kr[i*4 + 2] = _workingKey[4] & 0x1f;
            _Kr[i*4 + 3] = _workingKey[6] & 0x1f;


            // Km_(i) <- KAPPA
            _Km[i*4    ] = _workingKey[7];
            _Km[i*4 + 1] = _workingKey[5];
            _Km[i*4 + 2] = _workingKey[3];
            _Km[i*4 + 3] = _workingKey[1];
        }
        
    }

    /**
     * Encrypt the given input starting at the given offset and place
     * the result in the provided buffer starting at the given offset.
     *
     * @param src        The plaintext buffer
     * @param srcIndex    An offset into src
     * @param dst        The ciphertext buffer
     * @param dstIndex    An offset into dst
     */
    protected int encryptBlock(
        byte[] src, 
        int srcIndex,
        byte[] dst,
        int dstIndex)
    {

        int  result[] = new int[4];

        // process the input block 
        // batch the units up into 4x32 bit chunks and go for it

        int A = BytesTo32bits(src, srcIndex);
        int B = BytesTo32bits(src, srcIndex + 4);
        int C = BytesTo32bits(src, srcIndex + 8);
        int D = BytesTo32bits(src, srcIndex + 12);

        CAST_Encipher(A, B, C, D, result);

        // now stuff them into the destination block
        Bits32ToBytes(result[0], dst, dstIndex);
        Bits32ToBytes(result[1], dst, dstIndex + 4);
        Bits32ToBytes(result[2], dst, dstIndex + 8);
        Bits32ToBytes(result[3], dst, dstIndex + 12);

        return BLOCK_SIZE;
    }

    /**
     * Decrypt the given input starting at the given offset and place
     * the result in the provided buffer starting at the given offset.
     *
     * @param src        The plaintext buffer
     * @param srcIndex    An offset into src
     * @param dst        The ciphertext buffer
     * @param dstIndex    An offset into dst
     */
    protected int decryptBlock(
        byte[] src, 
        int srcIndex,
        byte[] dst,
        int dstIndex)
    {
        int  result[] = new int[4];

        // process the input block
        // batch the units up into 4x32 bit chunks and go for it
        int A = BytesTo32bits(src, srcIndex);
        int B = BytesTo32bits(src, srcIndex + 4);
        int C = BytesTo32bits(src, srcIndex + 8);
        int D = BytesTo32bits(src, srcIndex + 12);

        CAST_Decipher(A, B, C, D, result);

        // now stuff them into the destination block
        Bits32ToBytes(result[0], dst, dstIndex);
        Bits32ToBytes(result[1], dst, dstIndex + 4);
        Bits32ToBytes(result[2], dst, dstIndex + 8);
        Bits32ToBytes(result[3], dst, dstIndex + 12);

        return BLOCK_SIZE;
    }

    /**
     * Does the 12 quad rounds rounds to encrypt the block.
     * 
     * @param A    the 00-31  bits of the plaintext block
     * @param B    the 32-63  bits of the plaintext block
     * @param C    the 64-95  bits of the plaintext block
     * @param D    the 96-127 bits of the plaintext block
     * @param result the resulting ciphertext
     */
    protected final void CAST_Encipher(int A, int B, int C, int D,int result[])
    {
        int x;
        for (int i=0; i< 6; i++)
        {
            x = i*4;
            // BETA <- Qi(BETA)
            C ^= F1(D, _Km[x], _Kr[x]);
            B ^= F2(C, _Km[x + 1], _Kr[x + 1]);
            A ^= F3(B, _Km[x + 2], _Kr[x + 2]);
            D ^= F1(A, _Km[x + 3], _Kr[x + 3]);

        }

        for (int i=6; i<12; i++)
        {
            x = i*4;
            // BETA <- QBARi(BETA)
            D ^= F1(A, _Km[x + 3], _Kr[x + 3]);
            A ^= F3(B, _Km[x + 2], _Kr[x + 2]);
            B ^= F2(C, _Km[x + 1], _Kr[x + 1]);
            C ^= F1(D, _Km[x], _Kr[x]);

        }

        result[0] = A;
        result[1] = B;
        result[2] = C;
        result[3] = D;
    }

    /**
     * Does the 12 quad rounds rounds to decrypt the block.
     * 
     * @param A    the 00-31  bits of the ciphertext block
     * @param B    the 32-63  bits of the ciphertext block
     * @param C    the 64-95  bits of the ciphertext block
     * @param D    the 96-127 bits of the ciphertext block
     * @param result the resulting plaintext
     */
    protected final void CAST_Decipher(int A, int B, int C, int D,int result[])
    {
        int x;
        for (int i=0; i< 6; i++)
        {
            x = (11-i)*4;
            // BETA <- Qi(BETA)
            C ^= F1(D, _Km[x], _Kr[x]);
            B ^= F2(C, _Km[x + 1], _Kr[x + 1]);
            A ^= F3(B, _Km[x + 2], _Kr[x + 2]);
            D ^= F1(A, _Km[x + 3], _Kr[x + 3]);

        }

        for (int i=6; i<12; i++)
        {
            x = (11-i)*4;
            // BETA <- QBARi(BETA)
            D ^= F1(A, _Km[x + 3], _Kr[x + 3]);
            A ^= F3(B, _Km[x + 2], _Kr[x + 2]);
            B ^= F2(C, _Km[x + 1], _Kr[x + 1]);
            C ^= F1(D, _Km[x], _Kr[x]);

        }

        result[0] = A;
        result[1] = B;
        result[2] = C;
        result[3] = D;
    }

}
