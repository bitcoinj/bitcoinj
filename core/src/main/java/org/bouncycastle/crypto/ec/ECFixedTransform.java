package org.bouncycastle.crypto.ec;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

/**
 * this transforms the original randomness used for an ElGamal encryption by a fixed value.
 */
public class ECFixedTransform
    implements ECPairFactorTransform
{
    private ECPublicKeyParameters key;

    private BigInteger k;

    public ECFixedTransform(BigInteger k)
    {
        this.k = k;
    }

    /**
     * initialise the underlying EC ElGamal engine.
     *
     * @param param the necessary EC key parameters.
     */
    public void init(
        CipherParameters    param)
    {
        if (!(param instanceof ECPublicKeyParameters))
        {
            throw new IllegalArgumentException("ECPublicKeyParameters are required for fixed transform.");
        }

        this.key = (ECPublicKeyParameters)param;
    }

    /**
     * Transform an existing cipher text pair using the ElGamal algorithm. Note: it is assumed this
     * transform has been initialised with the same public key that was used to create the original
     * cipher text.
     *
     * @param cipherText the EC point to process.
     * @return returns a new ECPair representing the result of the process.
     */
    public ECPair transform(ECPair cipherText)
    {
        if (key == null)
        {
            throw new IllegalStateException("ECFixedTransform not initialised");
        }

        ECDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();

        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        BigInteger k = this.k.mod(n);

        ECPoint[] gamma_phi = new ECPoint[]{
            basePointMultiplier.multiply(ec.getG(), k).add(cipherText.getX()),
            key.getQ().multiply(k).add(cipherText.getY())
        };

        ec.getCurve().normalizeAll(gamma_phi);

        return new ECPair(gamma_phi[0], gamma_phi[1]);
    }

    /**
     * Return the last transform value used by the transform
     *
     * @return a BigInteger representing k value.
     */
    public BigInteger getTransformValue()
    {
        return k;
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
