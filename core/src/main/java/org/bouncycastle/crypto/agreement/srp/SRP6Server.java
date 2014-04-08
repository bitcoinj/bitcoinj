package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

/**
 * Implements the server side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
 * This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
 */
public class SRP6Server
{
    protected BigInteger N;
    protected BigInteger g;
    protected BigInteger v;

    protected SecureRandom random;
    protected Digest digest;

    protected BigInteger A;

    protected BigInteger b;
    protected BigInteger B;

    protected BigInteger u;
    protected BigInteger S;

    public SRP6Server()
    {
    }

    /**
     * Initialises the server to accept a new client authentication attempt
     * @param N The safe prime associated with the client's verifier
     * @param g The group parameter associated with the client's verifier
     * @param v The client's verifier
     * @param digest The digest algorithm associated with the client's verifier
     * @param random For key generation
     */
    public void init(BigInteger N, BigInteger g, BigInteger v, Digest digest, SecureRandom random)
    {
        this.N = N;
        this.g = g;
        this.v = v;

        this.random = random;
        this.digest = digest;
    }

    /**
     * Generates the server's credentials that are to be sent to the client.
     * @return The server's public value to the client
     */
    public BigInteger generateServerCredentials()
    {
        BigInteger k = SRP6Util.calculateK(digest, N, g);
        this.b = selectPrivateValue();
        this.B = k.multiply(v).mod(N).add(g.modPow(b, N)).mod(N);

        return B;
    }

    /**
     * Processes the client's credentials. If valid the shared secret is generated and returned.
     * @param clientA The client's credentials
     * @return A shared secret BigInteger
     * @throws CryptoException If client's credentials are invalid
     */
    public BigInteger calculateSecret(BigInteger clientA) throws CryptoException
    {
        this.A = SRP6Util.validatePublicValue(N, clientA);
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
        return v.modPow(u, N).multiply(A).mod(N).modPow(b, N);
    }
}
