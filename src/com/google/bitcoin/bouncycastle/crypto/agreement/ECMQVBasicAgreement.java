package com.google.bitcoin.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import com.google.bitcoin.bouncycastle.crypto.BasicAgreement;
import com.google.bitcoin.bouncycastle.crypto.CipherParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ECDomainParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.MQVPrivateParameters;
import com.google.bitcoin.bouncycastle.crypto.params.MQVPublicParameters;
import com.google.bitcoin.bouncycastle.math.ec.ECAlgorithms;
import com.google.bitcoin.bouncycastle.math.ec.ECConstants;
import com.google.bitcoin.bouncycastle.math.ec.ECPoint;

public class ECMQVBasicAgreement
    implements BasicAgreement
{
    MQVPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (MQVPrivateParameters)key;
    }

    public BigInteger calculateAgreement(CipherParameters pubKey)
    {
        MQVPublicParameters pubParams = (MQVPublicParameters)pubKey;

        ECPrivateKeyParameters staticPrivateKey = privParams.getStaticPrivateKey();

        ECPoint agreement = calculateMqvAgreement(staticPrivateKey.getParameters(), staticPrivateKey,
            privParams.getEphemeralPrivateKey(), privParams.getEphemeralPublicKey(),
            pubParams.getStaticPublicKey(), pubParams.getEphemeralPublicKey());

        return agreement.getX().toBigInteger();
    }

    // The ECMQV Primitive as described in SEC-1, 3.4
    private ECPoint calculateMqvAgreement(
        ECDomainParameters      parameters,
        ECPrivateKeyParameters  d1U,
        ECPrivateKeyParameters  d2U,
        ECPublicKeyParameters   Q2U,
        ECPublicKeyParameters   Q1V,
        ECPublicKeyParameters   Q2V)
    {
        BigInteger n = parameters.getN();
        int e = (n.bitLength() + 1) / 2;
        BigInteger powE = ECConstants.ONE.shiftLeft(e);

        // The Q2U public key is optional
        ECPoint q;
        if (Q2U == null)
        {
            q = parameters.getG().multiply(d2U.getD());
        }
        else
        {
            q = Q2U.getQ();
        }

        BigInteger x = q.getX().toBigInteger();
        BigInteger xBar = x.mod(powE);
        BigInteger Q2UBar = xBar.setBit(e);
        BigInteger s = d1U.getD().multiply(Q2UBar).mod(n).add(d2U.getD()).mod(n);

        BigInteger xPrime = Q2V.getQ().getX().toBigInteger();
        BigInteger xPrimeBar = xPrime.mod(powE);
        BigInteger Q2VBar = xPrimeBar.setBit(e);

        BigInteger hs = parameters.getH().multiply(s).mod(n);

//        ECPoint p = Q1V.getQ().multiply(Q2VBar).add(Q2V.getQ()).multiply(hs);
        ECPoint p = ECAlgorithms.sumOfTwoMultiplies(
            Q1V.getQ(), Q2VBar.multiply(hs).mod(n), Q2V.getQ(), hs);

        if (p.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid agreement value for MQV");
        }

        return p;
    }
}
