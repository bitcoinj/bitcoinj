package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * HMAC implementation based on original internet draft for HMAC (RFC 2104)
 * <p>
 * The difference is that padding is concatenated versus XORed with the key
 * <p>
 * H(K + opad, H(K + ipad, text))
 */
public class SSL3Mac
    implements Mac
{
    private final static byte IPAD_BYTE = (byte)0x36;
    private final static byte OPAD_BYTE = (byte)0x5C;

    static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    static final byte[] OPAD = genPad(OPAD_BYTE, 48);

    private Digest digest;

    private byte[] secret;
    private int padLength;

    /**
     * Base constructor for one of the standard digest algorithms that the byteLength of
     * the algorithm is know for. Behaviour is undefined for digests other than MD5 or SHA1.
     *
     * @param digest the digest.
     */
    public SSL3Mac(Digest digest)
    {
        this.digest = digest;

        if (digest.getDigestSize() == 20)
        {
            this.padLength = 40;
        }
        else
        {
            this.padLength = 48;
        }
    }

    public String getAlgorithmName()
    {
        return digest.getAlgorithmName() + "/SSL3MAC";
    }

    public Digest getUnderlyingDigest()
    {
        return digest;
    }

    public void init(CipherParameters params)
    {
        secret = Arrays.clone(((KeyParameter)params).getKey());

        reset();
    }

    public int getMacSize()
    {
        return digest.getDigestSize();
    }

    public void update(byte in)
    {
        digest.update(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        digest.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        byte[] tmp = new byte[digest.getDigestSize()];
        digest.doFinal(tmp, 0);

        digest.update(secret, 0, secret.length);
        digest.update(OPAD, 0, padLength);
        digest.update(tmp, 0, tmp.length);

        int len = digest.doFinal(out, outOff);

        reset();

        return len;
    }

    /**
     * Reset the mac generator.
     */
    public void reset()
    {
        digest.reset();
        digest.update(secret, 0, secret.length);
        digest.update(IPAD, 0, padLength);
    }

    private static byte[] genPad(byte b, int count)
    {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }
}
