package org.bouncycastle.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

/**
 * this does your basic ElGamal encryption algorithm using EC
 */
public class ECElGamalEncryptor
    implements ECEncryptor
{
    private ECPublicKeyParameters key;
    private SecureRandom          random;

    /**
     * initialise the encryptor.
     *
     * @param param the necessary EC key parameters.
     */
    public void init(
        CipherParameters    param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    p = (ParametersWithRandom)param;

            if (!(p.getParameters() instanceof ECPublicKeyParameters))
            {
                throw new IllegalArgumentException("ECPublicKeyParameters are required for encryption.");
            }
            this.key = (ECPublicKeyParameters)p.getParameters();
            this.random = p.getRandom();
        }
        else
        {
            if (!(param instanceof ECPublicKeyParameters))
            {
                throw new IllegalArgumentException("ECPublicKeyParameters are required for encryption.");
            }

            this.key = (ECPublicKeyParameters)param;
            this.random = new SecureRandom();
        }
    }

    /**
     * Process a single EC point using the basic ElGamal algorithm.
     *
     * @param point the EC point to process.
     * @return the result of the Elgamal process.
     */
    public ECPair encrypt(ECPoint point)
    {
        if (key == null)
        {
            throw new IllegalStateException("ECElGamalEncryptor not initialised");
        }

        ECDomainParameters ec = key.getParameters();
        BigInteger k = ECUtil.generateK(ec.getN(), random);

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        ECPoint[] gamma_phi = new ECPoint[]{
            basePointMultiplier.multiply(ec.getG(), k),
            key.getQ().multiply(k).add(point)
        };

        ec.getCurve().normalizeAll(gamma_phi);

        return new ECPair(gamma_phi[0], gamma_phi[1]);
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
