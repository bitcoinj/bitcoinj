package org.bouncycastle.crypto;

/**
 * General holding class for a commitment.
 */
public class Commitment
{
    private final byte[] secret;
    private final byte[] commitment;

    /**
     * Base constructor.
     *
     * @param secret  an encoding of the secret required to reveal the commitment.
     * @param commitment  an encoding of the sealed commitment.
     */
    public Commitment(byte[] secret, byte[] commitment)
    {
        this.secret = secret;
        this.commitment = commitment;
    }

    /**
     * The secret required to reveal the commitment.
     *
     * @return an encoding of the secret associated with the commitment.
     */
    public byte[] getSecret()
    {
        return secret;
    }

    /**
     * The sealed commitment.
     *
     * @return an encoding of the sealed commitment.
     */
    public byte[] getCommitment()
    {
        return commitment;
    }
}
