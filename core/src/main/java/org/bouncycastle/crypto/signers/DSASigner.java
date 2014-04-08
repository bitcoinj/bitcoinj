package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/**
 * The Digital Signature Algorithm - as described in "Handbook of Applied
 * Cryptography", pages 452 - 453.
 */
public class DSASigner
    implements DSA
{
    private final DSAKCalculator kCalculator;

    private DSAKeyParameters key;
    private SecureRandom    random;

    /**
     * Default configuration, random K values.
     */
    public DSASigner()
    {
        this.kCalculator = new RandomDSAKCalculator();
    }

    /**
     * Configuration with an alternate, possibly deterministic calculator of K.
     *
     * @param kCalculator a K value calculator.
     */
    public DSASigner(DSAKCalculator kCalculator)
    {
        this.kCalculator = kCalculator;
    }

    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom    rParam = (ParametersWithRandom)param;

                this.random = rParam.getRandom();
                this.key = (DSAPrivateKeyParameters)rParam.getParameters();
            }
            else
            {
                this.random = new SecureRandom();
                this.key = (DSAPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (DSAPublicKeyParameters)param;
        }
    }

    /**
     * generate a signature for the given message using the key we were
     * initialised with. For conventional DSA the message should be a SHA-1
     * hash of the message of interest.
     *
     * @param message the message that will be verified later.
     */
    public BigInteger[] generateSignature(
        byte[] message)
    {
        DSAParameters   params = key.getParameters();
        BigInteger      m = calculateE(params.getQ(), message);

        if (kCalculator.isDeterministic())
        {
            kCalculator.init(params.getQ(), ((DSAPrivateKeyParameters)key).getX(), message);
        }
        else
        {
            kCalculator.init(params.getQ(), random);
        }

        BigInteger  k = kCalculator.nextK();

        BigInteger  r = params.getG().modPow(k, params.getP()).mod(params.getQ());

        k = k.modInverse(params.getQ()).multiply(
                    m.add(((DSAPrivateKeyParameters)key).getX().multiply(r)));

        BigInteger  s = k.mod(params.getQ());

        BigInteger[]  res = new BigInteger[2];

        res[0] = r;
        res[1] = s;

        return res;
    }

    /**
     * return true if the value r and s represent a DSA signature for
     * the passed in message for standard DSA the message should be a
     * SHA-1 hash of the real message to be verified.
     */
    public boolean verifySignature(
        byte[]      message,
        BigInteger  r,
        BigInteger  s)
    {
        DSAParameters   params = key.getParameters();
        BigInteger      m = calculateE(params.getQ(), message);
        BigInteger      zero = BigInteger.valueOf(0);

        if (zero.compareTo(r) >= 0 || params.getQ().compareTo(r) <= 0)
        {
            return false;
        }

        if (zero.compareTo(s) >= 0 || params.getQ().compareTo(s) <= 0)
        {
            return false;
        }

        BigInteger  w = s.modInverse(params.getQ());

        BigInteger  u1 = m.multiply(w).mod(params.getQ());
        BigInteger  u2 = r.multiply(w).mod(params.getQ());

        u1 = params.getG().modPow(u1, params.getP());
        u2 = ((DSAPublicKeyParameters)key).getY().modPow(u2, params.getP());

        BigInteger  v = u1.multiply(u2).mod(params.getP()).mod(params.getQ());

        return v.equals(r);
    }

    private BigInteger calculateE(BigInteger n, byte[] message)
    {
        if (n.bitLength() >= message.length * 8)
        {
            return new BigInteger(1, message);
        }
        else
        {
            byte[] trunc = new byte[n.bitLength() / 8];

            System.arraycopy(message, 0, trunc, 0, trunc.length);

            return new BigInteger(1, trunc);
        }
    }
}
