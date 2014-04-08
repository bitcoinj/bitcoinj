package org.bouncycastle.crypto.prng.drbg;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * A SP800-90A CTR DRBG.
 */
public class CTRSP800DRBG
    implements SP80090DRBG
{
    private static final long       TDEA_RESEED_MAX = 1L << (32 - 1);
    private static final long       AES_RESEED_MAX = 1L << (48 - 1);
    private static final int        TDEA_MAX_BITS_REQUEST = 1 << (13 - 1);
    private static final int        AES_MAX_BITS_REQUEST = 1 << (19 - 1);

    private EntropySource          _entropySource;
    private BlockCipher           _engine;
    private int                   _keySizeInBits;
    private int                   _seedLength;
    
    // internal state
    private byte[]                _Key;
    private byte[]                _V;
    private long                  _reseedCounter = 0;
    private boolean               _isTDEA = false;

    /**
     * Construct a SP800-90A CTR DRBG.
     * <p>
     * Minimum entropy requirement is the security strength requested.
     * </p>
     * @param engine underlying block cipher to use to support DRBG
     * @param keySizeInBits size of the key to use with the block cipher.
     * @param securityStrength security strength required (in bits)
     * @param entropySource source of entropy to use for seeding/reseeding.
     * @param personalizationString personalization string to distinguish this DRBG (may be null).
     * @param nonce nonce to further distinguish this DRBG (may be null).
     */
    public CTRSP800DRBG(BlockCipher engine, int keySizeInBits, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce)
    {
        _entropySource = entropySource;
        _engine = engine;     
        
        _keySizeInBits = keySizeInBits;
        _seedLength = keySizeInBits + engine.getBlockSize() * 8;
        _isTDEA = isTDEA(engine);

        if (securityStrength > 256)
        {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }

        if (getMaxSecurityStrength(engine, keySizeInBits) < securityStrength)
        {
            throw new IllegalArgumentException("Requested security strength is not supported by block cipher and key size");
        }

        if (entropySource.entropySize() < securityStrength)
        {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        }

        byte[] entropy = entropySource.getEntropy();  // Get_entropy_input

        CTR_DRBG_Instantiate_algorithm(entropy, nonce, personalizationString);
    }

    private void CTR_DRBG_Instantiate_algorithm(byte[] entropy, byte[] nonce,
            byte[] personalisationString)
    {
        byte[] seedMaterial = Arrays.concatenate(entropy, nonce, personalisationString);
        byte[] seed = Block_Cipher_df(seedMaterial, _seedLength);

        int outlen = _engine.getBlockSize();

        _Key = new byte[(_keySizeInBits + 7) / 8];
        _V = new byte[outlen];

         // _Key & _V are modified by this call
        CTR_DRBG_Update(seed, _Key, _V); 

        _reseedCounter = 1;
    }

    private void CTR_DRBG_Update(byte[] seed, byte[] key, byte[] v)
    {
        byte[] temp = new byte[seed.length];
        byte[] outputBlock = new byte[_engine.getBlockSize()];
        
        int i=0;
        int outLen = _engine.getBlockSize();

        _engine.init(true, new KeyParameter(expandKey(key)));
        while (i*outLen < seed.length)
        {
            addOneTo(v);
            _engine.processBlock(v, 0, outputBlock, 0);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                    ? outLen : (temp.length - i * outLen);
            
            System.arraycopy(outputBlock, 0, temp, i * outLen, bytesToCopy);
            ++i;
        }

        XOR(temp, seed, temp, 0);

        System.arraycopy(temp, 0, key, 0, key.length);
        System.arraycopy(temp, key.length, v, 0, v.length);
    }
    
    private void CTR_DRBG_Reseed_algorithm(EntropySource entropy, byte[] additionalInput) 
    {
        byte[] seedMaterial = Arrays.concatenate(entropy.getEntropy(), additionalInput);

        seedMaterial = Block_Cipher_df(seedMaterial, _seedLength);

        CTR_DRBG_Update(seedMaterial, _Key, _V);

        _reseedCounter = 1;
    }

    private void XOR(byte[] out, byte[] a, byte[] b, int bOff)
    {
        for (int i=0; i< out.length; i++) 
        {
            out[i] = (byte)(a[i] ^ b[i+bOff]);
        }
    }
    
    private void addOneTo(byte[] longer)
    {
        int carry = 1;
        for (int i = 1; i <= longer.length; i++) // warning
        {
            int res = (longer[longer.length - i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length - i] = (byte)res;
        }
    } 
    
    // -- Internal state migration ---
    
    private static final byte[] K_BITS = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

    // 1. If (number_of_bits_to_return > max_number_of_bits), then return an
    // ERROR_FLAG.
    // 2. L = len (input_string)/8.
    // 3. N = number_of_bits_to_return/8.
    // Comment: L is the bitstring represention of
    // the integer resulting from len (input_string)/8.
    // L shall be represented as a 32-bit integer.
    //
    // Comment : N is the bitstring represention of
    // the integer resulting from
    // number_of_bits_to_return/8. N shall be
    // represented as a 32-bit integer.
    //
    // 4. S = L || N || input_string || 0x80.
    // 5. While (len (S) mod outlen)
    // Comment : Pad S with zeros, if necessary.
    // 0, S = S || 0x00.
    //
    // Comment : Compute the starting value.
    // 6. temp = the Null string.
    // 7. i = 0.
    // 8. K = Leftmost keylen bits of 0x00010203...1D1E1F.
    // 9. While len (temp) < keylen + outlen, do
    //
    // IV = i || 0outlen - len (i).
    //
    // 9.1
    //
    // temp = temp || BCC (K, (IV || S)).
    //
    // 9.2
    //
    // i = i + 1.
    //
    // 9.3
    //
    // Comment : i shall be represented as a 32-bit
    // integer, i.e., len (i) = 32.
    //
    // Comment: The 32-bit integer represenation of
    // i is padded with zeros to outlen bits.
    //
    // Comment: Compute the requested number of
    // bits.
    //
    // 10. K = Leftmost keylen bits of temp.
    //
    // 11. X = Next outlen bits of temp.
    //
    // 12. temp = the Null string.
    //
    // 13. While len (temp) < number_of_bits_to_return, do
    //
    // 13.1 X = Block_Encrypt (K, X).
    //
    // 13.2 temp = temp || X.
    //
    // 14. requested_bits = Leftmost number_of_bits_to_return of temp.
    //
    // 15. Return SUCCESS and requested_bits.
    private byte[] Block_Cipher_df(byte[] inputString, int bitLength)
    {
        int outLen = _engine.getBlockSize();
        int L = inputString.length; // already in bytes
        int N = bitLength / 8;
        // 4 S = L || N || inputstring || 0x80
        int sLen = 4 + 4 + L + 1;
        int blockLen = ((sLen + outLen - 1) / outLen) * outLen;
        byte[] S = new byte[blockLen];
        copyIntToByteArray(S, L, 0);
        copyIntToByteArray(S, N, 4);
        System.arraycopy(inputString, 0, S, 8, L);
        S[8 + L] = (byte)0x80;
        // S already padded with zeros

        byte[] temp = new byte[_keySizeInBits / 8 + outLen];
        byte[] bccOut = new byte[outLen];

        byte[] IV = new byte[outLen]; 
        
        int i = 0;
        byte[] K = new byte[_keySizeInBits / 8];
        System.arraycopy(K_BITS, 0, K, 0, K.length);

        while (i*outLen*8 < _keySizeInBits + outLen *8)
        {
            copyIntToByteArray(IV, i, 0);
            BCC(bccOut, K, IV, S);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                    ? outLen
                    : (temp.length - i * outLen);
            
            System.arraycopy(bccOut, 0, temp, i * outLen, bytesToCopy);
            ++i;
        }

        byte[] X = new byte[outLen];
        System.arraycopy(temp, 0, K, 0, K.length);
        System.arraycopy(temp, K.length, X, 0, X.length);

        temp = new byte[bitLength / 2];

        i = 0;
        _engine.init(true, new KeyParameter(expandKey(K)));

        while (i * outLen < temp.length)
        {
            _engine.processBlock(X, 0, X, 0);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                    ? outLen
                    : (temp.length - i * outLen);

            System.arraycopy(X, 0, temp, i * outLen, bytesToCopy);
            i++;
        }

        return temp;
    }

    /*
    * 1. chaining_value = 0^outlen    
    *    . Comment: Set the first chaining value to outlen zeros.
    * 2. n = len (data)/outlen.
    * 3. Starting with the leftmost bits of data, split the data into n blocks of outlen bits 
    *    each, forming block(1) to block(n). 
    * 4. For i = 1 to n do
    * 4.1 input_block = chaining_value ^ block(i) .
    * 4.2 chaining_value = Block_Encrypt (Key, input_block).
    * 5. output_block = chaining_value.
    * 6. Return output_block. 
     */
    private void BCC(byte[] bccOut, byte[] k, byte[] iV, byte[] data)
    {
        int outlen = _engine.getBlockSize();
        byte[] chainingValue = new byte[outlen]; // initial values = 0
        int n = data.length / outlen;

        byte[] inputBlock = new byte[outlen];

        _engine.init(true, new KeyParameter(expandKey(k)));

        _engine.processBlock(iV, 0, chainingValue, 0);

        for (int i = 0; i < n; i++)
        {
            XOR(inputBlock, chainingValue, data, i*outlen);
            _engine.processBlock(inputBlock, 0, chainingValue, 0);
        }

        System.arraycopy(chainingValue, 0, bccOut, 0, bccOut.length);
    }

    private void copyIntToByteArray(byte[] buf, int value, int offSet)
    {
        buf[offSet + 0] = ((byte)(value >> 24));
        buf[offSet + 1] = ((byte)(value >> 16));
        buf[offSet + 2] = ((byte)(value >> 8));
        buf[offSet + 3] = ((byte)(value));
    }

    /**
     * Return the block size (in bits) of the DRBG.
     *
     * @return the number of bits produced on each internal round of the DRBG.
     */
    public int getBlockSize()
    {
        return _V.length * 8;
    }

    /**
     * Populate a passed in array with random data.
     *
     * @param output output array for generated bits.
     * @param additionalInput additional input to be added to the DRBG in this step.
     * @param predictionResistant true if a reseed should be forced, false otherwise.
     *
     * @return number of bits generated, -1 if a reseed required.
     */
    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        if (_isTDEA)
        {
            if (_reseedCounter > TDEA_RESEED_MAX)
            {
                return -1;
            }

            if (Utils.isTooLarge(output, TDEA_MAX_BITS_REQUEST / 8))
            {
                throw new IllegalArgumentException("Number of bits per request limited to " + TDEA_MAX_BITS_REQUEST);
            }
        }
        else
        {
            if (_reseedCounter > AES_RESEED_MAX)
            {
                return -1;
            }

            if (Utils.isTooLarge(output, AES_MAX_BITS_REQUEST / 8))
            {
                throw new IllegalArgumentException("Number of bits per request limited to " + AES_MAX_BITS_REQUEST);
            }
        }

        if (predictionResistant)
        {
            CTR_DRBG_Reseed_algorithm(_entropySource, additionalInput);
            additionalInput = null;
        }

        if (additionalInput != null)
        {
            additionalInput = Block_Cipher_df(additionalInput, _seedLength);
            CTR_DRBG_Update(additionalInput, _Key, _V);
        }
        else
        {
            additionalInput = new byte[_seedLength];
        }

        byte[] out = new byte[_V.length];

        _engine.init(true, new KeyParameter(expandKey(_Key)));

        for (int i = 0; i < output.length / out.length; i++)
        {
            addOneTo(_V);

            _engine.processBlock(_V, 0, out, 0);

            int bytesToCopy = ((output.length - i * out.length) > out.length)
                    ? out.length
                    : (output.length - i * _V.length);

            System.arraycopy(out, 0, output, i * out.length, bytesToCopy);
        }

        CTR_DRBG_Update(additionalInput, _Key, _V);

        _reseedCounter++;

        return output.length * 8;
    }

    /**
      * Reseed the DRBG.
      *
      * @param additionalInput additional input to be added to the DRBG in this step.
      */
    public void reseed(byte[] additionalInput)
    {
        CTR_DRBG_Reseed_algorithm(_entropySource, additionalInput);
    }

    private boolean isTDEA(BlockCipher cipher)
    {
        return cipher.getAlgorithmName().equals("DESede") || cipher.getAlgorithmName().equals("TDEA");
    }

    private int getMaxSecurityStrength(BlockCipher cipher, int keySizeInBits)
    {
        if (isTDEA(cipher) && keySizeInBits == 168)
        {
            return 112;
        }
        if (cipher.getAlgorithmName().equals("AES"))
        {
            return keySizeInBits;
        }

        return -1;
    }

    byte[] expandKey(byte[] key)
    {
        if (_isTDEA)
        {
            // expand key to 192 bits.
            byte[] tmp = new byte[24];

            padKey(key, 0, tmp, 0);
            padKey(key, 7, tmp, 8);
            padKey(key, 14, tmp, 16);

            return tmp;
        }
        else
        {
            return key;
        }
    }

    /**
     * Pad out a key for TDEA, setting odd parity for each byte.
     *
     * @param keyMaster
     * @param keyOff
     * @param tmp
     * @param tmpOff
     */
    private void padKey(byte[] keyMaster, int keyOff, byte[] tmp, int tmpOff)
    {
        tmp[tmpOff + 0] = (byte)(keyMaster[keyOff + 0] & 0xfe);
        tmp[tmpOff + 1] = (byte)((keyMaster[keyOff + 0] << 7) | ((keyMaster[keyOff + 1] & 0xfc) >>> 1));
        tmp[tmpOff + 2] = (byte)((keyMaster[keyOff + 1] << 6) | ((keyMaster[keyOff + 2] & 0xf8) >>> 2));
        tmp[tmpOff + 3] = (byte)((keyMaster[keyOff + 2] << 5) | ((keyMaster[keyOff + 3] & 0xf0) >>> 3));
        tmp[tmpOff + 4] = (byte)((keyMaster[keyOff + 3] << 4) | ((keyMaster[keyOff + 4] & 0xe0) >>> 4));
        tmp[tmpOff + 5] = (byte)((keyMaster[keyOff + 4] << 3) | ((keyMaster[keyOff + 5] & 0xc0) >>> 5));
        tmp[tmpOff + 6] = (byte)((keyMaster[keyOff + 5] << 2) | ((keyMaster[keyOff + 6] & 0x80) >>> 6));
        tmp[tmpOff + 7] = (byte)(keyMaster[keyOff + 6] << 1);

        for (int i = tmpOff; i <= tmpOff + 7; i++)
        {
            int b = tmp[i];
            tmp[i] = (byte)((b & 0xfe) |
                            ((((b >> 1) ^
                            (b >> 2) ^
                            (b >> 3) ^
                            (b >> 4) ^
                            (b >> 5) ^
                            (b >> 6) ^
                            (b >> 7)) ^ 0x01) & 0x01));
        }
    }
}
