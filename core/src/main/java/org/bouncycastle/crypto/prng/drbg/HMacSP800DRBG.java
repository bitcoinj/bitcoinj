package org.bouncycastle.crypto.prng.drbg;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.Arrays;

/**
 * A SP800-90A HMAC DRBG.
 */
public class HMacSP800DRBG
    implements SP80090DRBG
{
    private final static long       RESEED_MAX = 1L << (48 - 1);
    private final static int        MAX_BITS_REQUEST = 1 << (19 - 1);

    private byte[] _K;
    private byte[] _V;
    private long   _reseedCounter;
    private EntropySource _entropySource;
    private Mac _hMac;

    /**
     * Construct a SP800-90A Hash DRBG.
     * <p>
     * Minimum entropy requirement is the security strength requested.
     * </p>
     * @param hMac Hash MAC to base the DRBG on.
     * @param securityStrength security strength required (in bits)
     * @param entropySource source of entropy to use for seeding/reseeding.
     * @param personalizationString personalization string to distinguish this DRBG (may be null).
     * @param nonce nonce to further distinguish this DRBG (may be null).
     */
    public HMacSP800DRBG(Mac hMac, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce)
    {
        if (securityStrength > Utils.getMaxSecurityStrength(hMac))
        {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }

        if (entropySource.entropySize() < securityStrength)
        {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        }

        _entropySource = entropySource;
        _hMac = hMac;

        byte[] entropy = entropySource.getEntropy();
        byte[] seedMaterial = Arrays.concatenate(entropy, nonce, personalizationString);

        _K = new byte[hMac.getMacSize()];
        _V = new byte[_K.length];
        Arrays.fill(_V, (byte)1);

        hmac_DRBG_Update(seedMaterial);

        _reseedCounter = 1;
    }

    private void hmac_DRBG_Update(byte[] seedMaterial)
    {
        hmac_DRBG_Update_Func(seedMaterial, (byte)0x00);
        if (seedMaterial != null)
        {
            hmac_DRBG_Update_Func(seedMaterial, (byte)0x01);
        }
    }

    private void hmac_DRBG_Update_Func(byte[] seedMaterial, byte vValue)
    {
        _hMac.init(new KeyParameter(_K));

        _hMac.update(_V, 0, _V.length);
        _hMac.update(vValue);

        if (seedMaterial != null)
        {
            _hMac.update(seedMaterial, 0, seedMaterial.length);
        }

        _hMac.doFinal(_K, 0);

        _hMac.init(new KeyParameter(_K));
        _hMac.update(_V, 0, _V.length);

        _hMac.doFinal(_V, 0);
    }

    /**
     * Return the block size (in bits) of the DRBG.
     *
     * @return the number of bits produced on each round of the DRBG.
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
        int numberOfBits = output.length * 8;

        if (numberOfBits > MAX_BITS_REQUEST)
        {
            throw new IllegalArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST);
        }

        if (_reseedCounter > RESEED_MAX)
        {
            return -1;
        }

        if (predictionResistant)
        {
            reseed(additionalInput);
            additionalInput = null;
        }

        // 2.
        if (additionalInput != null)
        {
            hmac_DRBG_Update(additionalInput);
        }

        // 3.
        byte[] rv = new byte[output.length];

        int m = output.length / _V.length;

        _hMac.init(new KeyParameter(_K));

        for (int i = 0; i < m; i++)
        {
            _hMac.update(_V, 0, _V.length);
            _hMac.doFinal(_V, 0);

            System.arraycopy(_V, 0, rv, i * _V.length, _V.length);
        }

        if (m * _V.length < rv.length)
        {
            _hMac.update(_V, 0, _V.length);
            _hMac.doFinal(_V, 0);

            System.arraycopy(_V, 0, rv, m * _V.length, rv.length - (m * _V.length));
        }

        hmac_DRBG_Update(additionalInput);

        _reseedCounter++;

        System.arraycopy(rv, 0, output, 0, output.length);

        return numberOfBits;
    }

    /**
      * Reseed the DRBG.
      *
      * @param additionalInput additional input to be added to the DRBG in this step.
      */
    public void reseed(byte[] additionalInput)
    {
        byte[] entropy = _entropySource.getEntropy();
        byte[] seedMaterial = Arrays.concatenate(entropy, additionalInput);

        hmac_DRBG_Update(seedMaterial);

        _reseedCounter = 1;
    }
}
