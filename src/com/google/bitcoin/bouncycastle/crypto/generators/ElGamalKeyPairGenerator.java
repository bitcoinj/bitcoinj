package com.google.bitcoin.bouncycastle.crypto.generators;

import java.math.BigInteger;

import com.google.bitcoin.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.google.bitcoin.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.google.bitcoin.bouncycastle.crypto.KeyGenerationParameters;
import com.google.bitcoin.bouncycastle.crypto.params.DHParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ElGamalParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ElGamalPublicKeyParameters;

/**
 * a ElGamal key pair generator.
 * <p>
 * This generates keys consistent for use with ElGamal as described in
 * page 164 of "Handbook of Applied Cryptography".
 */
public class ElGamalKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private ElGamalKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (ElGamalKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
        ElGamalParameters egp = param.getParameters();
        DHParameters dhp = new DHParameters(egp.getP(), egp.getG(), null, egp.getL());  

        BigInteger x = helper.calculatePrivate(dhp, param.getRandom()); 
        BigInteger y = helper.calculatePublic(dhp, x);

        return new AsymmetricCipherKeyPair(
            new ElGamalPublicKeyParameters(y, egp),
            new ElGamalPrivateKeyParameters(x, egp));
    }
}
