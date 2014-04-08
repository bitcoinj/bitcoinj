package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SkeinEngine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.SkeinParameters;

/**
 * Implementation of the Skein parameterised MAC function in 256, 512 and 1024 bit block sizes,
 * based on the {@link ThreefishEngine Threefish} tweakable block cipher.
 * <p>
 * This is the 1.3 version of Skein defined in the Skein hash function submission to the NIST SHA-3
 * competition in October 2010.
 * <p>
 * Skein was designed by Niels Ferguson - Stefan Lucks - Bruce Schneier - Doug Whiting - Mihir
 * Bellare - Tadayoshi Kohno - Jon Callas - Jesse Walker.
 *
 * @see SkeinEngine
 * @see SkeinParameters
 */
public class SkeinMac
    implements Mac
{
    /**
     * 256 bit block size - Skein MAC-256
     */
    public static final int SKEIN_256 = SkeinEngine.SKEIN_256;
    /**
     * 512 bit block size - Skein MAC-512
     */
    public static final int SKEIN_512 = SkeinEngine.SKEIN_512;
    /**
     * 1024 bit block size - Skein MAC-1024
     */
    public static final int SKEIN_1024 = SkeinEngine.SKEIN_1024;

    private SkeinEngine engine;

    /**
     * Constructs a Skein MAC with an internal state size and output size.
     *
     * @param stateSizeBits  the internal state size in bits - one of {@link #SKEIN_256}, {@link #SKEIN_512} or
     *                       {@link #SKEIN_1024}.
     * @param digestSizeBits the output/MAC size to produce in bits, which must be an integral number of bytes.
     */
    public SkeinMac(int stateSizeBits, int digestSizeBits)
    {
        this.engine = new SkeinEngine(stateSizeBits, digestSizeBits);
    }

    public SkeinMac(SkeinMac mac)
    {
        this.engine = new SkeinEngine(mac.engine);
    }

    public String getAlgorithmName()
    {
        return "Skein-MAC-" + (engine.getBlockSize() * 8) + "-" + (engine.getOutputSize() * 8);
    }

    /**
     * Initialises the Skein digest with the provided parameters.<br>
     * See {@link SkeinParameters} for details on the parameterisation of the Skein hash function.
     *
     * @param params an instance of {@link SkeinParameters} or {@link KeyParameter}.
     */
    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        SkeinParameters skeinParameters;
        if (params instanceof SkeinParameters)
        {
            skeinParameters = (SkeinParameters)params;
        }
        else if (params instanceof KeyParameter)
        {
            skeinParameters = new SkeinParameters.Builder().setKey(((KeyParameter)params).getKey()).build();
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameter passed to Skein MAC init - "
                + params.getClass().getName());
        }
        if (skeinParameters.getKey() == null)
        {
            throw new IllegalArgumentException("Skein MAC requires a key parameter.");
        }
        engine.init(skeinParameters);
    }

    public int getMacSize()
    {
        return engine.getOutputSize();
    }

    public void reset()
    {
        engine.reset();
    }

    public void update(byte in)
    {
        engine.update(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        engine.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        return engine.doFinal(out, outOff);
    }

}
