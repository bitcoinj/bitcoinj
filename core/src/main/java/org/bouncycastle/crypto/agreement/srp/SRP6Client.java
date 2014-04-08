package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

/**
 * Implements the client side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
 * This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
 */
public class SRP6Client
{
    protected BigInteger N;
    protected BigInteger g;

    protected BigInteger a;
    protected BigInteger A;

    protected BigInteger B;

    protected BigInteger x;
    protected BigInteger u;
    protected BigInteger S;

    protected Digest digest;
    protected SecureRandom random;

    public SRP6Client()
    {
    }

    /**
     * Initialises the client to begin new authentication attempt
     * @param N The safe prime associated with the client's verifier
     * @param g The group parameter associated with the client's verifier
     * @param digest The digest algorithm associated with the client's verifier
     * @param random For key generation
     */
    public void init(BigInteger N, BigInteger g, Digest digest, SecureRandom random)
    {
        this.N = N;
        this.g = g;
        this.digest = digest;
        this.random = random;
    }

    /**
     * Generates client's credentials given the client's salt, identity and password
     * @param salt The salt used in the client's verifier.
     * @param identity The user's identity (eg. username)
     * @param password The user's password
     * @return Client's public value to send to server
     */
    public BigInteger generateClientCredentials(byte[] salt, byte[] identity, byte[] password)
    {
        this.x = SRP6Util.calculateX(digest, N, salt, identity, password);
        this.a = selectPrivateValue();
        this.A = g.modPow(a, N);

        return A;
    }

    /**
     * Generates client's verification message given the server's credentials
     * @param serverB The server's credentials
     * @return Client's verification message for the server
     * @throws CryptoException If server's credentials are invalid
     */
    public BigInteger calculateSecret(BigInteger serverB) throws CryptoException
    {
        this.B = SRP6Util.validatePublicValue(N, serverB);
        this.u = SRP6Util.calculateU(digest, N, A, B);
        this.S = calculateS();

        return S;
    }

    protected BigInteger selectPrivateValue()
    {
        return SRP6Util.generatePrivateValue(digest, N, g, random);        
    }

    private BigInteger calculateS()
    {
        BigInteger k = SRP6Util.calculateK(digest, N, g);
        BigInteger exp = u.multiply(x).add(a);
        BigInteger tmp = g.modPow(x, N).multiply(k).mod(N);
        return B.subtract(tmp).mod(N).modPow(exp, N);
    }
}
