package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * an implementation of the AES (Rijndael), from FIPS-197.
 * <p>
 * For further details see: <a href="http://csrc.nist.gov/encryption/aes/">http://csrc.nist.gov/encryption/aes/</a>.
 *
 * This implementation is based on optimizations from Dr. Brian Gladman's paper and C code at
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 *
 * There are three levels of tradeoff of speed vs memory
 * Because java has no preprocessor, they are written as three separate classes from which to choose
 *
 * The fastest uses 8Kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
 * and 4 for decryption.
 *
 * The middle performance version uses only one 256 word table for each, for a total of 2Kbytes,
 * adding 12 rotate operations per round to compute the values contained in the other tables from
 * the contents of the first
 *
 * The slowest version uses no static tables at all and computes the values
 * in each round.
 * <p>
 * This file contains the slowest performance version with no static tables
 * for round precomputation, but it has the smallest foot print.
 *
 */
public class AESLightEngine
    implements BlockCipher
{
    // The S box
    private static final byte[] S = {
        (byte)99, (byte)124, (byte)119, (byte)123, (byte)242, (byte)107, (byte)111, (byte)197,
        (byte)48,   (byte)1, (byte)103,  (byte)43, (byte)254, (byte)215, (byte)171, (byte)118,
        (byte)202, (byte)130, (byte)201, (byte)125, (byte)250,  (byte)89,  (byte)71, (byte)240,
        (byte)173, (byte)212, (byte)162, (byte)175, (byte)156, (byte)164, (byte)114, (byte)192,
        (byte)183, (byte)253, (byte)147,  (byte)38,  (byte)54,  (byte)63, (byte)247, (byte)204,
        (byte)52, (byte)165, (byte)229, (byte)241, (byte)113, (byte)216,  (byte)49,  (byte)21,
        (byte)4, (byte)199,  (byte)35, (byte)195,  (byte)24, (byte)150,   (byte)5, (byte)154,
        (byte)7,  (byte)18, (byte)128, (byte)226, (byte)235,  (byte)39, (byte)178, (byte)117,
        (byte)9, (byte)131,  (byte)44,  (byte)26,  (byte)27, (byte)110,  (byte)90, (byte)160,
        (byte)82,  (byte)59, (byte)214, (byte)179,  (byte)41, (byte)227,  (byte)47, (byte)132,
        (byte)83, (byte)209,   (byte)0, (byte)237,  (byte)32, (byte)252, (byte)177,  (byte)91,
        (byte)106, (byte)203, (byte)190,  (byte)57,  (byte)74,  (byte)76,  (byte)88, (byte)207,
        (byte)208, (byte)239, (byte)170, (byte)251,  (byte)67,  (byte)77,  (byte)51, (byte)133,
        (byte)69, (byte)249,   (byte)2, (byte)127,  (byte)80,  (byte)60, (byte)159, (byte)168,
        (byte)81, (byte)163,  (byte)64, (byte)143, (byte)146, (byte)157,  (byte)56, (byte)245,
        (byte)188, (byte)182, (byte)218,  (byte)33,  (byte)16, (byte)255, (byte)243, (byte)210,
        (byte)205,  (byte)12,  (byte)19, (byte)236,  (byte)95, (byte)151,  (byte)68,  (byte)23,
        (byte)196, (byte)167, (byte)126,  (byte)61, (byte)100,  (byte)93,  (byte)25, (byte)115,
        (byte)96, (byte)129,  (byte)79, (byte)220,  (byte)34,  (byte)42, (byte)144, (byte)136,
        (byte)70, (byte)238, (byte)184,  (byte)20, (byte)222,  (byte)94,  (byte)11, (byte)219,
        (byte)224,  (byte)50,  (byte)58,  (byte)10,  (byte)73,   (byte)6,  (byte)36,  (byte)92,
        (byte)194, (byte)211, (byte)172,  (byte)98, (byte)145, (byte)149, (byte)228, (byte)121,
        (byte)231, (byte)200,  (byte)55, (byte)109, (byte)141, (byte)213,  (byte)78, (byte)169,
        (byte)108,  (byte)86, (byte)244, (byte)234, (byte)101, (byte)122, (byte)174,   (byte)8,
        (byte)186, (byte)120,  (byte)37,  (byte)46,  (byte)28, (byte)166, (byte)180, (byte)198,
        (byte)232, (byte)221, (byte)116,  (byte)31,  (byte)75, (byte)189, (byte)139, (byte)138,
        (byte)112,  (byte)62, (byte)181, (byte)102,  (byte)72,   (byte)3, (byte)246,  (byte)14,
        (byte)97,  (byte)53,  (byte)87, (byte)185, (byte)134, (byte)193,  (byte)29, (byte)158,
        (byte)225, (byte)248, (byte)152,  (byte)17, (byte)105, (byte)217, (byte)142, (byte)148,
        (byte)155,  (byte)30, (byte)135, (byte)233, (byte)206,  (byte)85,  (byte)40, (byte)223,
        (byte)140, (byte)161, (byte)137,  (byte)13, (byte)191, (byte)230,  (byte)66, (byte)104,
        (byte)65, (byte)153,  (byte)45,  (byte)15, (byte)176,  (byte)84, (byte)187,  (byte)22,
    };

    // The inverse S-box
    private static final byte[] Si = {
        (byte)82,   (byte)9, (byte)106, (byte)213,  (byte)48,  (byte)54, (byte)165,  (byte)56,
        (byte)191,  (byte)64, (byte)163, (byte)158, (byte)129, (byte)243, (byte)215, (byte)251,
        (byte)124, (byte)227,  (byte)57, (byte)130, (byte)155,  (byte)47, (byte)255, (byte)135,
        (byte)52, (byte)142,  (byte)67,  (byte)68, (byte)196, (byte)222, (byte)233, (byte)203,
        (byte)84, (byte)123, (byte)148,  (byte)50, (byte)166, (byte)194,  (byte)35,  (byte)61,
        (byte)238,  (byte)76, (byte)149,  (byte)11,  (byte)66, (byte)250, (byte)195,  (byte)78,
        (byte)8,  (byte)46, (byte)161, (byte)102,  (byte)40, (byte)217,  (byte)36, (byte)178,
        (byte)118,  (byte)91, (byte)162,  (byte)73, (byte)109, (byte)139, (byte)209,  (byte)37,
        (byte)114, (byte)248, (byte)246, (byte)100, (byte)134, (byte)104, (byte)152,  (byte)22,
        (byte)212, (byte)164,  (byte)92, (byte)204,  (byte)93, (byte)101, (byte)182, (byte)146,
        (byte)108, (byte)112,  (byte)72,  (byte)80, (byte)253, (byte)237, (byte)185, (byte)218,
        (byte)94,  (byte)21,  (byte)70,  (byte)87, (byte)167, (byte)141, (byte)157, (byte)132,
        (byte)144, (byte)216, (byte)171,   (byte)0, (byte)140, (byte)188, (byte)211,  (byte)10,
        (byte)247, (byte)228,  (byte)88,   (byte)5, (byte)184, (byte)179,  (byte)69,   (byte)6,
        (byte)208,  (byte)44,  (byte)30, (byte)143, (byte)202,  (byte)63,  (byte)15,   (byte)2,
        (byte)193, (byte)175, (byte)189,   (byte)3,   (byte)1,  (byte)19, (byte)138, (byte)107,
        (byte)58, (byte)145,  (byte)17,  (byte)65,  (byte)79, (byte)103, (byte)220, (byte)234,
        (byte)151, (byte)242, (byte)207, (byte)206, (byte)240, (byte)180, (byte)230, (byte)115,
        (byte)150, (byte)172, (byte)116,  (byte)34, (byte)231, (byte)173,  (byte)53, (byte)133,
        (byte)226, (byte)249,  (byte)55, (byte)232,  (byte)28, (byte)117, (byte)223, (byte)110,
        (byte)71, (byte)241,  (byte)26, (byte)113,  (byte)29,  (byte)41, (byte)197, (byte)137,
        (byte)111, (byte)183,  (byte)98,  (byte)14, (byte)170,  (byte)24, (byte)190,  (byte)27,
        (byte)252,  (byte)86,  (byte)62,  (byte)75, (byte)198, (byte)210, (byte)121,  (byte)32,
        (byte)154, (byte)219, (byte)192, (byte)254, (byte)120, (byte)205,  (byte)90, (byte)244,
        (byte)31, (byte)221, (byte)168,  (byte)51, (byte)136,   (byte)7, (byte)199,  (byte)49,
        (byte)177,  (byte)18,  (byte)16,  (byte)89,  (byte)39, (byte)128, (byte)236,  (byte)95,
        (byte)96,  (byte)81, (byte)127, (byte)169,  (byte)25, (byte)181,  (byte)74,  (byte)13,
        (byte)45, (byte)229, (byte)122, (byte)159, (byte)147, (byte)201, (byte)156, (byte)239,
        (byte)160, (byte)224,  (byte)59,  (byte)77, (byte)174,  (byte)42, (byte)245, (byte)176,
        (byte)200, (byte)235, (byte)187,  (byte)60, (byte)131,  (byte)83, (byte)153,  (byte)97,
        (byte)23,  (byte)43,   (byte)4, (byte)126, (byte)186, (byte)119, (byte)214,  (byte)38,
        (byte)225, (byte)105,  (byte)20,  (byte)99,  (byte)85,  (byte)33,  (byte)12, (byte)125,
        };

    // vector used in calculating key schedule (powers of x in GF(256))
    private static final int[] rcon = {
         0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
         0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 };

    private static int shift(int r, int shift)
    {
        return (r >>> shift) | (r << -shift);
    }

    /* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

    private static final int m1 = 0x80808080;
    private static final int m2 = 0x7f7f7f7f;
    private static final int m3 = 0x0000001b;

    private static int FFmulX(int x)
    {
        return (((x & m2) << 1) ^ (((x & m1) >>> 7) * m3));
    }

    /* 
       The following defines provide alternative definitions of FFmulX that might
       give improved performance if a fast 32-bit multiply is not available.
       
       private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); } 
       private static final int  m4 = 0x1b1b1b1b;
       private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); } 

    */

    private static int mcol(int x)
    {
        int f2 = FFmulX(x);
        return f2 ^ shift(x ^ f2, 8) ^ shift(x, 16) ^ shift(x, 24);
    }

    private static int inv_mcol(int x)
    {
        int f2 = FFmulX(x);
        int f4 = FFmulX(f2);
        int f8 = FFmulX(f4);
        int f9 = x ^ f8;
        
        return f2 ^ f4 ^ f8 ^ shift(f2 ^ f9, 8) ^ shift(f4 ^ f9, 16) ^ shift(f9, 24);
    }


    private static int subWord(int x)
    {
        return (S[x&255]&255 | ((S[(x>>8)&255]&255)<<8) | ((S[(x>>16)&255]&255)<<16) | S[(x>>24)&255]<<24);
    }

    /**
     * Calculate the necessary round keys
     * The number of calculations depends on key size and block size
     * AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
     * This code is written assuming those are the only possible values
     */
    private int[][] generateWorkingKey(
                                    byte[] key,
                                    boolean forEncryption)
    {
        int         KC = key.length / 4;  // key length in words
        int         t;
        
        if (((KC != 4) && (KC != 6) && (KC != 8)) || ((KC * 4) != key.length))
        {
            throw new IllegalArgumentException("Key length not 128/192/256 bits.");
        }

        ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
        int[][] W = new int[ROUNDS+1][4];   // 4 words in a block
        
        //
        // copy the key into the round key array
        //
        
        t = 0;
        int i = 0;
        while (i < key.length)
            {
                W[t >> 2][t & 3] = (key[i]&0xff) | ((key[i+1]&0xff) << 8) | ((key[i+2]&0xff) << 16) | (key[i+3] << 24);
                i+=4;
                t++;
            }
        
        //
        // while not enough round key material calculated
        // calculate new values
        //
        int k = (ROUNDS + 1) << 2;
        for (i = KC; (i < k); i++)
            {
                int temp = W[(i-1)>>2][(i-1)&3];
                if ((i % KC) == 0)
                {
                    temp = subWord(shift(temp, 8)) ^ rcon[(i / KC)-1];
                }
                else if ((KC > 6) && ((i % KC) == 4))
                {
                    temp = subWord(temp);
                }
                
                W[i>>2][i&3] = W[(i - KC)>>2][(i-KC)&3] ^ temp;
            }

        if (!forEncryption)
        {
            for (int j = 1; j < ROUNDS; j++)
            {
                for (i = 0; i < 4; i++) 
                {
                    W[j][i] = inv_mcol(W[j][i]);
                }
            }
        }

        return W;
    }

    private int         ROUNDS;
    private int[][]     WorkingKey = null;
    private int         C0, C1, C2, C3;
    private boolean     forEncryption;

    private static final int BLOCK_SIZE = 16;

    /**
     * default constructor - 128 bit block size.
     */
    public AESLightEngine()
    {
    }

    /**
     * initialise an AES cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           forEncryption,
        CipherParameters  params)
    {
        if (params instanceof KeyParameter)
        {
            WorkingKey = generateWorkingKey(((KeyParameter)params).getKey(), forEncryption);
            this.forEncryption = forEncryption;
            return;
        }

        throw new IllegalArgumentException("invalid parameter passed to AES init - " + params.getClass().getName());
    }

    public String getAlgorithmName()
    {
        return "AES";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
    {
        if (WorkingKey == null)
        {
            throw new IllegalStateException("AES engine not initialised");
        }

        if ((inOff + (32 / 2)) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + (32 / 2)) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        if (forEncryption)
        {
            unpackBlock(in, inOff);
            encryptBlock(WorkingKey);
            packBlock(out, outOff);
        }
        else
        {
            unpackBlock(in, inOff);
            decryptBlock(WorkingKey);
            packBlock(out, outOff);
        }

        return BLOCK_SIZE;
    }

    public void reset()
    {
    }

    private void unpackBlock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        C0 = (bytes[index++] & 0xff);
        C0 |= (bytes[index++] & 0xff) << 8;
        C0 |= (bytes[index++] & 0xff) << 16;
        C0 |= bytes[index++] << 24;

        C1 = (bytes[index++] & 0xff);
        C1 |= (bytes[index++] & 0xff) << 8;
        C1 |= (bytes[index++] & 0xff) << 16;
        C1 |= bytes[index++] << 24;

        C2 = (bytes[index++] & 0xff);
        C2 |= (bytes[index++] & 0xff) << 8;
        C2 |= (bytes[index++] & 0xff) << 16;
        C2 |= bytes[index++] << 24;

        C3 = (bytes[index++] & 0xff);
        C3 |= (bytes[index++] & 0xff) << 8;
        C3 |= (bytes[index++] & 0xff) << 16;
        C3 |= bytes[index++] << 24;
    }

    private void packBlock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        bytes[index++] = (byte)C0;
        bytes[index++] = (byte)(C0 >> 8);
        bytes[index++] = (byte)(C0 >> 16);
        bytes[index++] = (byte)(C0 >> 24);

        bytes[index++] = (byte)C1;
        bytes[index++] = (byte)(C1 >> 8);
        bytes[index++] = (byte)(C1 >> 16);
        bytes[index++] = (byte)(C1 >> 24);

        bytes[index++] = (byte)C2;
        bytes[index++] = (byte)(C2 >> 8);
        bytes[index++] = (byte)(C2 >> 16);
        bytes[index++] = (byte)(C2 >> 24);

        bytes[index++] = (byte)C3;
        bytes[index++] = (byte)(C3 >> 8);
        bytes[index++] = (byte)(C3 >> 16);
        bytes[index++] = (byte)(C3 >> 24);
    }

    private void encryptBlock(int[][] KW)
    {
        int r, r0, r1, r2, r3;

        C0 ^= KW[0][0];
        C1 ^= KW[0][1];
        C2 ^= KW[0][2];
        C3 ^= KW[0][3];

        for (r = 1; r < ROUNDS - 1;)
        {
            r0 = mcol((S[C0&255]&255) ^ ((S[(C1>>8)&255]&255)<<8) ^ ((S[(C2>>16)&255]&255)<<16) ^ (S[(C3>>24)&255]<<24)) ^ KW[r][0];
            r1 = mcol((S[C1&255]&255) ^ ((S[(C2>>8)&255]&255)<<8) ^ ((S[(C3>>16)&255]&255)<<16) ^ (S[(C0>>24)&255]<<24)) ^ KW[r][1];
            r2 = mcol((S[C2&255]&255) ^ ((S[(C3>>8)&255]&255)<<8) ^ ((S[(C0>>16)&255]&255)<<16) ^ (S[(C1>>24)&255]<<24)) ^ KW[r][2];
            r3 = mcol((S[C3&255]&255) ^ ((S[(C0>>8)&255]&255)<<8) ^ ((S[(C1>>16)&255]&255)<<16) ^ (S[(C2>>24)&255]<<24)) ^ KW[r++][3];
            C0 = mcol((S[r0&255]&255) ^ ((S[(r1>>8)&255]&255)<<8) ^ ((S[(r2>>16)&255]&255)<<16) ^ (S[(r3>>24)&255]<<24)) ^ KW[r][0];
            C1 = mcol((S[r1&255]&255) ^ ((S[(r2>>8)&255]&255)<<8) ^ ((S[(r3>>16)&255]&255)<<16) ^ (S[(r0>>24)&255]<<24)) ^ KW[r][1];
            C2 = mcol((S[r2&255]&255) ^ ((S[(r3>>8)&255]&255)<<8) ^ ((S[(r0>>16)&255]&255)<<16) ^ (S[(r1>>24)&255]<<24)) ^ KW[r][2];
            C3 = mcol((S[r3&255]&255) ^ ((S[(r0>>8)&255]&255)<<8) ^ ((S[(r1>>16)&255]&255)<<16) ^ (S[(r2>>24)&255]<<24)) ^ KW[r++][3];
        }

        r0 = mcol((S[C0&255]&255) ^ ((S[(C1>>8)&255]&255)<<8) ^ ((S[(C2>>16)&255]&255)<<16) ^ (S[(C3>>24)&255]<<24)) ^ KW[r][0];
        r1 = mcol((S[C1&255]&255) ^ ((S[(C2>>8)&255]&255)<<8) ^ ((S[(C3>>16)&255]&255)<<16) ^ (S[(C0>>24)&255]<<24)) ^ KW[r][1];
        r2 = mcol((S[C2&255]&255) ^ ((S[(C3>>8)&255]&255)<<8) ^ ((S[(C0>>16)&255]&255)<<16) ^ (S[(C1>>24)&255]<<24)) ^ KW[r][2];
        r3 = mcol((S[C3&255]&255) ^ ((S[(C0>>8)&255]&255)<<8) ^ ((S[(C1>>16)&255]&255)<<16) ^ (S[(C2>>24)&255]<<24)) ^ KW[r++][3];

        // the final round is a simple function of S

        C0 = (S[r0&255]&255) ^ ((S[(r1>>8)&255]&255)<<8) ^ ((S[(r2>>16)&255]&255)<<16) ^ (S[(r3>>24)&255]<<24) ^ KW[r][0];
        C1 = (S[r1&255]&255) ^ ((S[(r2>>8)&255]&255)<<8) ^ ((S[(r3>>16)&255]&255)<<16) ^ (S[(r0>>24)&255]<<24) ^ KW[r][1];
        C2 = (S[r2&255]&255) ^ ((S[(r3>>8)&255]&255)<<8) ^ ((S[(r0>>16)&255]&255)<<16) ^ (S[(r1>>24)&255]<<24) ^ KW[r][2];
        C3 = (S[r3&255]&255) ^ ((S[(r0>>8)&255]&255)<<8) ^ ((S[(r1>>16)&255]&255)<<16) ^ (S[(r2>>24)&255]<<24) ^ KW[r][3];

    }

    private void decryptBlock(int[][] KW)
    {
        int r, r0, r1, r2, r3;

        C0 ^= KW[ROUNDS][0];
        C1 ^= KW[ROUNDS][1];
        C2 ^= KW[ROUNDS][2];
        C3 ^= KW[ROUNDS][3];

        for (r = ROUNDS-1; r>1;)
        {
            r0 = inv_mcol((Si[C0&255]&255) ^ ((Si[(C3>>8)&255]&255)<<8) ^ ((Si[(C2>>16)&255]&255)<<16) ^ (Si[(C1>>24)&255]<<24)) ^ KW[r][0];
            r1 = inv_mcol((Si[C1&255]&255) ^ ((Si[(C0>>8)&255]&255)<<8) ^ ((Si[(C3>>16)&255]&255)<<16) ^ (Si[(C2>>24)&255]<<24)) ^ KW[r][1];
            r2 = inv_mcol((Si[C2&255]&255) ^ ((Si[(C1>>8)&255]&255)<<8) ^ ((Si[(C0>>16)&255]&255)<<16) ^ (Si[(C3>>24)&255]<<24)) ^ KW[r][2];
            r3 = inv_mcol((Si[C3&255]&255) ^ ((Si[(C2>>8)&255]&255)<<8) ^ ((Si[(C1>>16)&255]&255)<<16) ^ (Si[(C0>>24)&255]<<24)) ^ KW[r--][3];
            C0 = inv_mcol((Si[r0&255]&255) ^ ((Si[(r3>>8)&255]&255)<<8) ^ ((Si[(r2>>16)&255]&255)<<16) ^ (Si[(r1>>24)&255]<<24)) ^ KW[r][0];
            C1 = inv_mcol((Si[r1&255]&255) ^ ((Si[(r0>>8)&255]&255)<<8) ^ ((Si[(r3>>16)&255]&255)<<16) ^ (Si[(r2>>24)&255]<<24)) ^ KW[r][1];
            C2 = inv_mcol((Si[r2&255]&255) ^ ((Si[(r1>>8)&255]&255)<<8) ^ ((Si[(r0>>16)&255]&255)<<16) ^ (Si[(r3>>24)&255]<<24)) ^ KW[r][2];
            C3 = inv_mcol((Si[r3&255]&255) ^ ((Si[(r2>>8)&255]&255)<<8) ^ ((Si[(r1>>16)&255]&255)<<16) ^ (Si[(r0>>24)&255]<<24)) ^ KW[r--][3];
        }

        r0 = inv_mcol((Si[C0&255]&255) ^ ((Si[(C3>>8)&255]&255)<<8) ^ ((Si[(C2>>16)&255]&255)<<16) ^ (Si[(C1>>24)&255]<<24)) ^ KW[r][0];
        r1 = inv_mcol((Si[C1&255]&255) ^ ((Si[(C0>>8)&255]&255)<<8) ^ ((Si[(C3>>16)&255]&255)<<16) ^ (Si[(C2>>24)&255]<<24)) ^ KW[r][1];
        r2 = inv_mcol((Si[C2&255]&255) ^ ((Si[(C1>>8)&255]&255)<<8) ^ ((Si[(C0>>16)&255]&255)<<16) ^ (Si[(C3>>24)&255]<<24)) ^ KW[r][2];
        r3 = inv_mcol((Si[C3&255]&255) ^ ((Si[(C2>>8)&255]&255)<<8) ^ ((Si[(C1>>16)&255]&255)<<16) ^ (Si[(C0>>24)&255]<<24)) ^ KW[r][3];

        // the final round's table is a simple function of Si

        C0 = (Si[r0&255]&255) ^ ((Si[(r3>>8)&255]&255)<<8) ^ ((Si[(r2>>16)&255]&255)<<16) ^ (Si[(r1>>24)&255]<<24) ^ KW[0][0];
        C1 = (Si[r1&255]&255) ^ ((Si[(r0>>8)&255]&255)<<8) ^ ((Si[(r3>>16)&255]&255)<<16) ^ (Si[(r2>>24)&255]<<24) ^ KW[0][1];
        C2 = (Si[r2&255]&255) ^ ((Si[(r1>>8)&255]&255)<<8) ^ ((Si[(r0>>16)&255]&255)<<16) ^ (Si[(r3>>24)&255]<<24) ^ KW[0][2];
        C3 = (Si[r3&255]&255) ^ ((Si[(r2>>8)&255]&255)<<8) ^ ((Si[(r1>>16)&255]&255)<<16) ^ (Si[(r0>>24)&255]<<24) ^ KW[0][3];
    }
}
