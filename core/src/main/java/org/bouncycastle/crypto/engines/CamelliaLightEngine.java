package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Camellia - based on RFC 3713, smaller implementation, about half the size of CamelliaEngine.
 */

public class CamelliaLightEngine
    implements BlockCipher
{
    private static final int BLOCK_SIZE = 16;
    private static final int MASK8 = 0xff;
    private boolean initialized;
    private boolean _keyis128;

    private int[] subkey = new int[24 * 4];
    private int[] kw = new int[4 * 2]; // for whitening
    private int[] ke = new int[6 * 2]; // for FL and FL^(-1)
    private int[] state = new int[4]; // for encryption and decryption

    private static final int SIGMA[] = {
        0xa09e667f, 0x3bcc908b,
        0xb67ae858, 0x4caa73b2,
        0xc6ef372f, 0xe94f82be,
        0x54ff53a5, 0xf1d36f1c,
        0x10e527fa, 0xde682d1d,
        0xb05688c2, 0xb3e6c1fd
    };

    /*
    *
    * S-box data
    *
    */
    private static final byte SBOX1[] = {
        (byte)112, (byte)130, (byte)44, (byte)236,
        (byte)179, (byte)39, (byte)192, (byte)229,
        (byte)228, (byte)133, (byte)87, (byte)53,
        (byte)234, (byte)12, (byte)174, (byte)65,
        (byte)35, (byte)239, (byte)107, (byte)147,
        (byte)69, (byte)25, (byte)165, (byte)33,
        (byte)237, (byte)14, (byte)79, (byte)78,
        (byte)29, (byte)101, (byte)146, (byte)189,
        (byte)134, (byte)184, (byte)175, (byte)143,
        (byte)124, (byte)235, (byte)31, (byte)206,
        (byte)62, (byte)48, (byte)220, (byte)95,
        (byte)94, (byte)197, (byte)11, (byte)26,
        (byte)166, (byte)225, (byte)57, (byte)202,
        (byte)213, (byte)71, (byte)93, (byte)61,
        (byte)217, (byte)1, (byte)90, (byte)214,
        (byte)81, (byte)86, (byte)108, (byte)77,
        (byte)139, (byte)13, (byte)154, (byte)102,
        (byte)251, (byte)204, (byte)176, (byte)45,
        (byte)116, (byte)18, (byte)43, (byte)32,
        (byte)240, (byte)177, (byte)132, (byte)153,
        (byte)223, (byte)76, (byte)203, (byte)194,
        (byte)52, (byte)126, (byte)118, (byte)5,
        (byte)109, (byte)183, (byte)169, (byte)49,
        (byte)209, (byte)23, (byte)4, (byte)215,
        (byte)20, (byte)88, (byte)58, (byte)97,
        (byte)222, (byte)27, (byte)17, (byte)28,
        (byte)50, (byte)15, (byte)156, (byte)22,
        (byte)83, (byte)24, (byte)242, (byte)34,
        (byte)254, (byte)68, (byte)207, (byte)178,
        (byte)195, (byte)181, (byte)122, (byte)145,
        (byte)36, (byte)8, (byte)232, (byte)168,
        (byte)96, (byte)252, (byte)105, (byte)80,
        (byte)170, (byte)208, (byte)160, (byte)125,
        (byte)161, (byte)137, (byte)98, (byte)151,
        (byte)84, (byte)91, (byte)30, (byte)149,
        (byte)224, (byte)255, (byte)100, (byte)210,
        (byte)16, (byte)196, (byte)0, (byte)72,
        (byte)163, (byte)247, (byte)117, (byte)219,
        (byte)138, (byte)3, (byte)230, (byte)218,
        (byte)9, (byte)63, (byte)221, (byte)148,
        (byte)135, (byte)92, (byte)131, (byte)2,
        (byte)205, (byte)74, (byte)144, (byte)51,
        (byte)115, (byte)103, (byte)246, (byte)243,
        (byte)157, (byte)127, (byte)191, (byte)226,
        (byte)82, (byte)155, (byte)216, (byte)38,
        (byte)200, (byte)55, (byte)198, (byte)59,
        (byte)129, (byte)150, (byte)111, (byte)75,
        (byte)19, (byte)190, (byte)99, (byte)46,
        (byte)233, (byte)121, (byte)167, (byte)140,
        (byte)159, (byte)110, (byte)188, (byte)142,
        (byte)41, (byte)245, (byte)249, (byte)182,
        (byte)47, (byte)253, (byte)180, (byte)89,
        (byte)120, (byte)152, (byte)6, (byte)106,
        (byte)231, (byte)70, (byte)113, (byte)186,
        (byte)212, (byte)37, (byte)171, (byte)66,
        (byte)136, (byte)162, (byte)141, (byte)250,
        (byte)114, (byte)7, (byte)185, (byte)85,
        (byte)248, (byte)238, (byte)172, (byte)10,
        (byte)54, (byte)73, (byte)42, (byte)104,
        (byte)60, (byte)56, (byte)241, (byte)164,
        (byte)64, (byte)40, (byte)211, (byte)123,
        (byte)187, (byte)201, (byte)67, (byte)193,
        (byte)21, (byte)227, (byte)173, (byte)244,
        (byte)119, (byte)199, (byte)128, (byte)158
    };

    private static int rightRotate(int x, int s)
    {
        return (((x) >>> (s)) + ((x) << (32 - s)));
    }

    private static int leftRotate(int x, int s)
    {
        return ((x) << (s)) + ((x) >>> (32 - s));
    }

    private static void roldq(int rot, int[] ki, int ioff,
                                    int[] ko, int ooff)
    {
        ko[0 + ooff] = (ki[0 + ioff] << rot) | (ki[1 + ioff] >>> (32 - rot));
        ko[1 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >>> (32 - rot));
        ko[2 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >>> (32 - rot));
        ko[3 + ooff] = (ki[3 + ioff] << rot) | (ki[0 + ioff] >>> (32 - rot));
        ki[0 + ioff] = ko[0 + ooff];
        ki[1 + ioff] = ko[1 + ooff];
        ki[2 + ioff] = ko[2 + ooff];
        ki[3 + ioff] = ko[3 + ooff];
    }

    private static void decroldq(int rot, int[] ki, int ioff,
                                       int[] ko, int ooff)
    {
        ko[2 + ooff] = (ki[0 + ioff] << rot) | (ki[1 + ioff] >>> (32 - rot));
        ko[3 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >>> (32 - rot));
        ko[0 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >>> (32 - rot));
        ko[1 + ooff] = (ki[3 + ioff] << rot) | (ki[0 + ioff] >>> (32 - rot));
        ki[0 + ioff] = ko[2 + ooff];
        ki[1 + ioff] = ko[3 + ooff];
        ki[2 + ioff] = ko[0 + ooff];
        ki[3 + ioff] = ko[1 + ooff];
    }

    private static void roldqo32(int rot, int[] ki, int ioff,
                                       int[] ko, int ooff)
    {
        ko[0 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >>> (64 - rot));
        ko[1 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >>> (64 - rot));
        ko[2 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[0 + ioff] >>> (64 - rot));
        ko[3 + ooff] = (ki[0 + ioff] << (rot - 32)) | (ki[1 + ioff] >>> (64 - rot));
        ki[0 + ioff] = ko[0 + ooff];
        ki[1 + ioff] = ko[1 + ooff];
        ki[2 + ioff] = ko[2 + ooff];
        ki[3 + ioff] = ko[3 + ooff];
    }

    private static void decroldqo32(int rot, int[] ki, int ioff,
                                          int[] ko, int ooff)
    {
        ko[2 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >>> (64 - rot));
        ko[3 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >>> (64 - rot));
        ko[0 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[0 + ioff] >>> (64 - rot));
        ko[1 + ooff] = (ki[0 + ioff] << (rot - 32)) | (ki[1 + ioff] >>> (64 - rot));
        ki[0 + ioff] = ko[2 + ooff];
        ki[1 + ioff] = ko[3 + ooff];
        ki[2 + ioff] = ko[0 + ooff];
        ki[3 + ioff] = ko[1 + ooff];
    }

    private int bytes2int(byte[] src, int offset)
    {
        int word = 0;

        for (int i = 0; i < 4; i++)
        {
            word = (word << 8) + (src[i + offset] & MASK8);
        }
        return word;
    }

    private void int2bytes(int word, byte[] dst, int offset)
    {
        for (int i = 0; i < 4; i++)
        {
            dst[(3 - i) + offset] = (byte)word;
            word >>>= 8;
        }
    }

    private byte lRot8(byte v, int rot)
    {
        return (byte)((v << rot) | ((v & 0xff) >>> (8 - rot)));
    }

    private int sbox2(int x)
    {
        return (lRot8(SBOX1[x], 1) & MASK8);
    }

    private int sbox3(int x)
    {
        return (lRot8(SBOX1[x], 7) & MASK8);
    }

    private int sbox4(int x)
    {
        return (SBOX1[((int)lRot8((byte)x, 1) & MASK8)] & MASK8);
    }

    private void camelliaF2(int[] s, int[] skey, int keyoff)
    {
        int t1, t2, u, v;

        t1 = s[0] ^ skey[0 + keyoff];
        u = sbox4((t1 & MASK8));
        u |= (sbox3(((t1 >>> 8) & MASK8)) << 8);
        u |= (sbox2(((t1 >>> 16) & MASK8)) << 16);
        u |= ((int)(SBOX1[((t1 >>> 24) & MASK8)] & MASK8) << 24);

        t2 = s[1] ^ skey[1 + keyoff];
        v = (int)SBOX1[(t2 & MASK8)] & MASK8;
        v |= (sbox4(((t2 >>> 8) & MASK8)) << 8);
        v |= (sbox3(((t2 >>> 16) & MASK8)) << 16);
        v |= (sbox2(((t2 >>> 24) & MASK8)) << 24);

        v = leftRotate(v, 8);
        u ^= v;
        v = leftRotate(v, 8) ^ u;
        u = rightRotate(u, 8) ^ v;
        s[2] ^= leftRotate(v, 16) ^ u;
        s[3] ^= leftRotate(u, 8);

        t1 = s[2] ^ skey[2 + keyoff];
        u = sbox4((t1 & MASK8));
        u |= sbox3(((t1 >>> 8) & MASK8)) << 8;
        u |= sbox2(((t1 >>> 16) & MASK8)) << 16;
        u |= ((int)SBOX1[((t1 >>> 24) & MASK8)] & MASK8) << 24;

        t2 = s[3] ^ skey[3 + keyoff];
        v = ((int)SBOX1[(t2 & MASK8)] & MASK8);
        v |= sbox4(((t2 >>> 8) & MASK8)) << 8;
        v |= sbox3(((t2 >>> 16) & MASK8)) << 16;
        v |= sbox2(((t2 >>> 24) & MASK8)) << 24;

        v = leftRotate(v, 8);
        u ^= v;
        v = leftRotate(v, 8) ^ u;
        u = rightRotate(u, 8) ^ v;
        s[0] ^= leftRotate(v, 16) ^ u;
        s[1] ^= leftRotate(u, 8);
    }

    private void camelliaFLs(int[] s, int[] fkey, int keyoff)
    {

        s[1] ^= leftRotate(s[0] & fkey[0 + keyoff], 1);
        s[0] ^= fkey[1 + keyoff] | s[1];

        s[2] ^= fkey[3 + keyoff] | s[3];
        s[3] ^= leftRotate(fkey[2 + keyoff] & s[2], 1);
    }

    private void setKey(boolean forEncryption, byte[] key)
    {
        int[] k = new int[8];
        int[] ka = new int[4];
        int[] kb = new int[4];
        int[] t = new int[4];

        switch (key.length)
        {
            case 16:
                _keyis128 = true;
                k[0] = bytes2int(key, 0);
                k[1] = bytes2int(key, 4);
                k[2] = bytes2int(key, 8);
                k[3] = bytes2int(key, 12);
                k[4] = k[5] = k[6] = k[7] = 0;
                break;
            case 24:
                k[0] = bytes2int(key, 0);
                k[1] = bytes2int(key, 4);
                k[2] = bytes2int(key, 8);
                k[3] = bytes2int(key, 12);
                k[4] = bytes2int(key, 16);
                k[5] = bytes2int(key, 20);
                k[6] = ~k[4];
                k[7] = ~k[5];
                _keyis128 = false;
                break;
            case 32:
                k[0] = bytes2int(key, 0);
                k[1] = bytes2int(key, 4);
                k[2] = bytes2int(key, 8);
                k[3] = bytes2int(key, 12);
                k[4] = bytes2int(key, 16);
                k[5] = bytes2int(key, 20);
                k[6] = bytes2int(key, 24);
                k[7] = bytes2int(key, 28);
                _keyis128 = false;
                break;
            default:
                throw new
                    IllegalArgumentException("key sizes are only 16/24/32 bytes.");
        }

        for (int i = 0; i < 4; i++)
        {
            ka[i] = k[i] ^ k[i + 4];
        }
        /* compute KA */
        camelliaF2(ka, SIGMA, 0);
        for (int i = 0; i < 4; i++)
        {
            ka[i] ^= k[i];
        }
        camelliaF2(ka, SIGMA, 4);

        if (_keyis128)
        {
            if (forEncryption)
            {
                /* KL dependant keys */
                kw[0] = k[0];
                kw[1] = k[1];
                kw[2] = k[2];
                kw[3] = k[3];
                roldq(15, k, 0, subkey, 4);
                roldq(30, k, 0, subkey, 12);
                roldq(15, k, 0, t, 0);
                subkey[18] = t[2];
                subkey[19] = t[3];
                roldq(17, k, 0, ke, 4);
                roldq(17, k, 0, subkey, 24);
                roldq(17, k, 0, subkey, 32);
                /* KA dependant keys */
                subkey[0] = ka[0];
                subkey[1] = ka[1];
                subkey[2] = ka[2];
                subkey[3] = ka[3];
                roldq(15, ka, 0, subkey, 8);
                roldq(15, ka, 0, ke, 0);
                roldq(15, ka, 0, t, 0);
                subkey[16] = t[0];
                subkey[17] = t[1];
                roldq(15, ka, 0, subkey, 20);
                roldqo32(34, ka, 0, subkey, 28);
                roldq(17, ka, 0, kw, 4);

            }
            else
            { // decryption
                /* KL dependant keys */
                kw[4] = k[0];
                kw[5] = k[1];
                kw[6] = k[2];
                kw[7] = k[3];
                decroldq(15, k, 0, subkey, 28);
                decroldq(30, k, 0, subkey, 20);
                decroldq(15, k, 0, t, 0);
                subkey[16] = t[0];
                subkey[17] = t[1];
                decroldq(17, k, 0, ke, 0);
                decroldq(17, k, 0, subkey, 8);
                decroldq(17, k, 0, subkey, 0);
                /* KA dependant keys */
                subkey[34] = ka[0];
                subkey[35] = ka[1];
                subkey[32] = ka[2];
                subkey[33] = ka[3];
                decroldq(15, ka, 0, subkey, 24);
                decroldq(15, ka, 0, ke, 4);
                decroldq(15, ka, 0, t, 0);
                subkey[18] = t[2];
                subkey[19] = t[3];
                decroldq(15, ka, 0, subkey, 12);
                decroldqo32(34, ka, 0, subkey, 4);
                roldq(17, ka, 0, kw, 0);
            }
        }
        else
        { // 192bit or 256bit
            /* compute KB */
            for (int i = 0; i < 4; i++)
            {
                kb[i] = ka[i] ^ k[i + 4];
            }
            camelliaF2(kb, SIGMA, 8);

            if (forEncryption)
            {
                /* KL dependant keys */
                kw[0] = k[0];
                kw[1] = k[1];
                kw[2] = k[2];
                kw[3] = k[3];
                roldqo32(45, k, 0, subkey, 16);
                roldq(15, k, 0, ke, 4);
                roldq(17, k, 0, subkey, 32);
                roldqo32(34, k, 0, subkey, 44);
                /* KR dependant keys */
                roldq(15, k, 4, subkey, 4);
                roldq(15, k, 4, ke, 0);
                roldq(30, k, 4, subkey, 24);
                roldqo32(34, k, 4, subkey, 36);
                /* KA dependant keys */
                roldq(15, ka, 0, subkey, 8);
                roldq(30, ka, 0, subkey, 20);
                /* 32bit rotation */
                ke[8] = ka[1];
                ke[9] = ka[2];
                ke[10] = ka[3];
                ke[11] = ka[0];
                roldqo32(49, ka, 0, subkey, 40);

                /* KB dependant keys */
                subkey[0] = kb[0];
                subkey[1] = kb[1];
                subkey[2] = kb[2];
                subkey[3] = kb[3];
                roldq(30, kb, 0, subkey, 12);
                roldq(30, kb, 0, subkey, 28);
                roldqo32(51, kb, 0, kw, 4);

            }
            else
            { // decryption
                /* KL dependant keys */
                kw[4] = k[0];
                kw[5] = k[1];
                kw[6] = k[2];
                kw[7] = k[3];
                decroldqo32(45, k, 0, subkey, 28);
                decroldq(15, k, 0, ke, 4);
                decroldq(17, k, 0, subkey, 12);
                decroldqo32(34, k, 0, subkey, 0);
                /* KR dependant keys */
                decroldq(15, k, 4, subkey, 40);
                decroldq(15, k, 4, ke, 8);
                decroldq(30, k, 4, subkey, 20);
                decroldqo32(34, k, 4, subkey, 8);
                /* KA dependant keys */
                decroldq(15, ka, 0, subkey, 36);
                decroldq(30, ka, 0, subkey, 24);
                /* 32bit rotation */
                ke[2] = ka[1];
                ke[3] = ka[2];
                ke[0] = ka[3];
                ke[1] = ka[0];
                decroldqo32(49, ka, 0, subkey, 4);

                /* KB dependant keys */
                subkey[46] = kb[0];
                subkey[47] = kb[1];
                subkey[44] = kb[2];
                subkey[45] = kb[3];
                decroldq(30, kb, 0, subkey, 32);
                decroldq(30, kb, 0, subkey, 16);
                roldqo32(51, kb, 0, kw, 0);
            }
        }
    }

    private int processBlock128(byte[] in, int inOff,
                                      byte[] out, int outOff)
    {
        for (int i = 0; i < 4; i++)
        {
            state[i] = bytes2int(in, inOff + (i * 4));
            state[i] ^= kw[i];
        }

        camelliaF2(state, subkey, 0);
        camelliaF2(state, subkey, 4);
        camelliaF2(state, subkey, 8);
        camelliaFLs(state, ke, 0);
        camelliaF2(state, subkey, 12);
        camelliaF2(state, subkey, 16);
        camelliaF2(state, subkey, 20);
        camelliaFLs(state, ke, 4);
        camelliaF2(state, subkey, 24);
        camelliaF2(state, subkey, 28);
        camelliaF2(state, subkey, 32);

        state[2] ^= kw[4];
        state[3] ^= kw[5];
        state[0] ^= kw[6];
        state[1] ^= kw[7];

        int2bytes(state[2], out, outOff);
        int2bytes(state[3], out, outOff + 4);
        int2bytes(state[0], out, outOff + 8);
        int2bytes(state[1], out, outOff + 12);

        return BLOCK_SIZE;
    }

    private int processBlock192or256(byte[] in, int inOff,
                                           byte[] out, int outOff)
    {
        for (int i = 0; i < 4; i++)
        {
            state[i] = bytes2int(in, inOff + (i * 4));
            state[i] ^= kw[i];
        }

        camelliaF2(state, subkey, 0);
        camelliaF2(state, subkey, 4);
        camelliaF2(state, subkey, 8);
        camelliaFLs(state, ke, 0);
        camelliaF2(state, subkey, 12);
        camelliaF2(state, subkey, 16);
        camelliaF2(state, subkey, 20);
        camelliaFLs(state, ke, 4);
        camelliaF2(state, subkey, 24);
        camelliaF2(state, subkey, 28);
        camelliaF2(state, subkey, 32);
        camelliaFLs(state, ke, 8);
        camelliaF2(state, subkey, 36);
        camelliaF2(state, subkey, 40);
        camelliaF2(state, subkey, 44);

        state[2] ^= kw[4];
        state[3] ^= kw[5];
        state[0] ^= kw[6];
        state[1] ^= kw[7];

        int2bytes(state[2], out, outOff);
        int2bytes(state[3], out, outOff + 4);
        int2bytes(state[0], out, outOff + 8);
        int2bytes(state[1], out, outOff + 12);
        return BLOCK_SIZE;
    }

    public CamelliaLightEngine()
    {
    }

    public String getAlgorithmName()
    {
        return "Camellia";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    public void init(boolean forEncryption, CipherParameters params)
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException("only simple KeyParameter expected.");
        }

        setKey(forEncryption, ((KeyParameter)params).getKey());
        initialized = true;
    }

    public int processBlock(byte[] in, int inOff,
                            byte[] out, int outOff)
        throws IllegalStateException
    {

        if (!initialized)
        {
            throw new IllegalStateException("Camellia is not initialized");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }
        
        if (_keyis128)
        {
            return processBlock128(in, inOff, out, outOff);
        }
        else
        {
            return processBlock192or256(in, inOff, out, outOff);
        }
    }

    public void reset()
    {
    }
}
