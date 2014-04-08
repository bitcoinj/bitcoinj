package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class VMPCEngine implements StreamCipher
{
    /*
     * variables to hold the state of the VMPC engine during encryption and
     * decryption
     */
    protected byte n = 0;
    protected byte[] P = null;
    protected byte s = 0;

    protected byte[] workingIV;
    protected byte[] workingKey;

    public String getAlgorithmName()
    {
        return "VMPC";
    }

    /**
     * initialise a VMPC cipher.
     * 
     * @param forEncryption
     *    whether or not we are for encryption.
     * @param params
     *    the parameters required to set up the cipher.
     * @exception IllegalArgumentException
     *    if the params argument is inappropriate.
     */
    public void init(boolean forEncryption, CipherParameters params)
    {
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException(
                "VMPC init parameters must include an IV");
        }

        ParametersWithIV ivParams = (ParametersWithIV) params;

        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException(
                "VMPC init parameters must include a key");
        }

        KeyParameter key = (KeyParameter) ivParams.getParameters();

        this.workingIV = ivParams.getIV();

        if (workingIV == null || workingIV.length < 1 || workingIV.length > 768)
        {
            throw new IllegalArgumentException("VMPC requires 1 to 768 bytes of IV");
        }

        this.workingKey = key.getKey();

        initKey(this.workingKey, this.workingIV);
    }

    protected void initKey(byte[] keyBytes, byte[] ivBytes)
    {
        s = 0;
        P = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            P[i] = (byte) i;
        }

        for (int m = 0; m < 768; m++)
        {
            s = P[(s + P[m & 0xff] + keyBytes[m % keyBytes.length]) & 0xff];
            byte temp = P[m & 0xff];
            P[m & 0xff] = P[s & 0xff];
            P[s & 0xff] = temp;
        }
        for (int m = 0; m < 768; m++)
        {
            s = P[(s + P[m & 0xff] + ivBytes[m % ivBytes.length]) & 0xff];
            byte temp = P[m & 0xff];
            P[m & 0xff] = P[s & 0xff];
            P[s & 0xff] = temp;
        }
        n = 0;
    }

    public void processBytes(byte[] in, int inOff, int len, byte[] out,
        int outOff)
    {
        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + len) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        for (int i = 0; i < len; i++)
        {
            s = P[(s + P[n & 0xff]) & 0xff];
            byte z = P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff];
            // encryption
            byte temp = P[n & 0xff];
            P[n & 0xff] = P[s & 0xff];
            P[s & 0xff] = temp;
            n = (byte) ((n + 1) & 0xff);

            // xor
            out[i + outOff] = (byte) (in[i + inOff] ^ z);
        }
    }

    public void reset()
    {
        initKey(this.workingKey, this.workingIV);
    }

    public byte returnByte(byte in)
    {
        s = P[(s + P[n & 0xff]) & 0xff];
        byte z = P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff];
        // encryption
        byte temp = P[n & 0xff];
        P[n & 0xff] = P[s & 0xff];
        P[s & 0xff] = temp;
        n = (byte) ((n + 1) & 0xff);

        // xor
        return (byte) (in ^ z);
    }
}
