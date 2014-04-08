package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import java.math.BigInteger;

/**
 * This does your basic RSA Chaum's blinding and unblinding as outlined in
 * "Handbook of Applied Cryptography", page 475. You need to use this if you are
 * trying to get another party to generate signatures without them being aware
 * of the message they are signing.
 */
public class RSABlindingEngine
    implements AsymmetricBlockCipher
{
    private RSACoreEngine core = new RSACoreEngine();

    private RSAKeyParameters key;
    private BigInteger blindingFactor;

    private boolean forEncryption;

    /**
     * Initialise the blinding engine.
     *
     * @param forEncryption true if we are encrypting (blinding), false otherwise.
     * @param param         the necessary RSA key parameters.
     */
    public void init(
        boolean forEncryption,
        CipherParameters param)
    {
        RSABlindingParameters p;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;

            p = (RSABlindingParameters)rParam.getParameters();
        }
        else
        {
            p = (RSABlindingParameters)param;
        }

        core.init(forEncryption, p.getPublicKey());

        this.forEncryption = forEncryption;
        this.key = p.getPublicKey();
        this.blindingFactor = p.getBlindingFactor();
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
        return core.getInputBlockSize();
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
        return core.getOutputBlockSize();
    }

    /**
     * Process a single block using the RSA blinding algorithm.
     *
     * @param in    the input array.
     * @param inOff the offset into the input buffer where the data starts.
     * @param inLen the length of the data to be processed.
     * @return the result of the RSA process.
     * @throws DataLengthException the input block is too large.
     */
    public byte[] processBlock(
        byte[] in,
        int inOff,
        int inLen)
    {
        BigInteger msg = core.convertInput(in, inOff, inLen);

        if (forEncryption)
        {
            msg = blindMessage(msg);
        }
        else
        {
            msg = unblindMessage(msg);
        }

        return core.convertOutput(msg);
    }

    /*
     * Blind message with the blind factor.
     */
    private BigInteger blindMessage(
        BigInteger msg)
    {
        BigInteger blindMsg = blindingFactor;
        blindMsg = msg.multiply(blindMsg.modPow(key.getExponent(), key.getModulus()));
        blindMsg = blindMsg.mod(key.getModulus());

        return blindMsg;
    }

    /*
     * Unblind the message blinded with the blind factor.
     */
    private BigInteger unblindMessage(
        BigInteger blindedMsg)
    {
        BigInteger m = key.getModulus();
        BigInteger msg = blindedMsg;
        BigInteger blindFactorInverse = blindingFactor.modInverse(m);
        msg = msg.multiply(blindFactorInverse);
        msg = msg.mod(m);

        return msg;
    }
}
