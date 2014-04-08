package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.math.BigInteger;

/**
 * this does your basic RSA algorithm.
 */
class RSACoreEngine
{
    private RSAKeyParameters key;
    private boolean          forEncryption;

    /**
     * initialise the RSA engine.
     *
     * @param forEncryption true if we are encrypting, false otherwise.
     * @param param the necessary RSA key parameters.
     */
    public void init(
        boolean          forEncryption,
        CipherParameters param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    rParam = (ParametersWithRandom)param;

            key = (RSAKeyParameters)rParam.getParameters();
        }
        else
        {
            key = (RSAKeyParameters)param;
        }

        this.forEncryption = forEncryption;
    }

    /**
     * Return the maximum size for an input block to this engine.
     * For RSA this is always one byte less than the key size on
     * encryption, and the same length as the key size on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getInputBlockSize()
    {
        int     bitSize = key.getModulus().bitLength();

        if (forEncryption)
        {
            return (bitSize + 7) / 8 - 1;
        }
        else
        {
            return (bitSize + 7) / 8;
        }
    }

    /**
     * Return the maximum size for an output block to this engine.
     * For RSA this is always one byte less than the key size on
     * decryption, and the same length as the key size on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getOutputBlockSize()
    {
        int     bitSize = key.getModulus().bitLength();

        if (forEncryption)
        {
            return (bitSize + 7) / 8;
        }
        else
        {
            return (bitSize + 7) / 8 - 1;
        }
    }

    public BigInteger convertInput(
        byte[]  in,
        int     inOff,
        int     inLen)
    {
        if (inLen > (getInputBlockSize() + 1))
        {
            throw new DataLengthException("input too large for RSA cipher.");
        }
        else if (inLen == (getInputBlockSize() + 1) && !forEncryption)
        {
            throw new DataLengthException("input too large for RSA cipher.");
        }

        byte[]  block;

        if (inOff != 0 || inLen != in.length)
        {
            block = new byte[inLen];

            System.arraycopy(in, inOff, block, 0, inLen);
        }
        else
        {
            block = in;
        }

        BigInteger res = new BigInteger(1, block);
        if (res.compareTo(key.getModulus()) >= 0)
        {
            throw new DataLengthException("input too large for RSA cipher.");
        }

        return res;
    }

    public byte[] convertOutput(
        BigInteger result)
    {
        byte[]      output = result.toByteArray();

        if (forEncryption)
        {
            if (output[0] == 0 && output.length > getOutputBlockSize())        // have ended up with an extra zero byte, copy down.
            {
                byte[]  tmp = new byte[output.length - 1];

                System.arraycopy(output, 1, tmp, 0, tmp.length);

                return tmp;
            }

            if (output.length < getOutputBlockSize())     // have ended up with less bytes than normal, lengthen
            {
                byte[]  tmp = new byte[getOutputBlockSize()];

                System.arraycopy(output, 0, tmp, tmp.length - output.length, output.length);

                return tmp;
            }
        }
        else
        {
            if (output[0] == 0)        // have ended up with an extra zero byte, copy down.
            {
                byte[]  tmp = new byte[output.length - 1];

                System.arraycopy(output, 1, tmp, 0, tmp.length);

                return tmp;
            }
        }

        return output;
    }

    public BigInteger processBlock(BigInteger input)
    {
        if (key instanceof RSAPrivateCrtKeyParameters)
        {
            //
            // we have the extra factors, use the Chinese Remainder Theorem - the author
            // wishes to express his thanks to Dirk Bonekaemper at rtsffm.com for
            // advice regarding the expression of this.
            //
            RSAPrivateCrtKeyParameters crtKey = (RSAPrivateCrtKeyParameters)key;

            BigInteger p = crtKey.getP();
            BigInteger q = crtKey.getQ();
            BigInteger dP = crtKey.getDP();
            BigInteger dQ = crtKey.getDQ();
            BigInteger qInv = crtKey.getQInv();

            BigInteger mP, mQ, h, m;

            // mP = ((input mod p) ^ dP)) mod p
            mP = (input.remainder(p)).modPow(dP, p);

            // mQ = ((input mod q) ^ dQ)) mod q
            mQ = (input.remainder(q)).modPow(dQ, q);

            // h = qInv * (mP - mQ) mod p
            h = mP.subtract(mQ);
            h = h.multiply(qInv);
            h = h.mod(p);               // mod (in Java) returns the positive residual

            // m = h * q + mQ
            m = h.multiply(q);
            m = m.add(mQ);

            return m;
        }
        else
        {
            return input.modPow(
                        key.getExponent(), key.getModulus());
        }
    }
}
