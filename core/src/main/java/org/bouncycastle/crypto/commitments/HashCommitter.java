package org.bouncycastle.crypto.commitments;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.Committer;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;

/**
 * A basic hash-committer as described in "Making Mix Nets Robust for Electronic Voting by Randomized Partial Checking",
 * by Jakobsson, Juels, and Rivest (11th Usenix Security Symposium, 2002).
 * <p>
 * Use this class if you can enforce fixed length for messages. If you need something more general, use the GeneralHashCommitter.
 * </p>
 */
public class HashCommitter
    implements Committer
{
    private final Digest digest;
    private final int byteLength;
    private final SecureRandom random;

    /**
     * Base Constructor. The maximum message length that can be committed to is half the length of the internal
     * block size for the digest (ExtendedDigest.getBlockLength()).
     *
     * @param digest digest to use for creating commitments.
     * @param random source of randomness for generating secrets.
     */
    public HashCommitter(ExtendedDigest digest, SecureRandom random)
    {
        this.digest = digest;
        this.byteLength = digest.getByteLength();
        this.random = random;
    }

    /**
     * Generate a commitment for the passed in message.
     *
     * @param message the message to be committed to,
     * @return a Commitment
     */
    public Commitment commit(byte[] message)
    {
        if (message.length > byteLength / 2)
        {
            throw new DataLengthException("Message to be committed to too large for digest.");
        }

        byte[] w = new byte[byteLength - message.length];

        random.nextBytes(w);

        return new Commitment(w, calculateCommitment(w, message));
    }

    /**
     * Return true if the passed in commitment represents a commitment to the passed in message.
     *
     * @param commitment a commitment previously generated.
     * @param message the message that was expected to have been committed to.
     * @return true if commitment matches message, false otherwise.
     */
    public boolean isRevealed(Commitment commitment, byte[] message)
    {
        if (message.length + commitment.getSecret().length != byteLength)
        {
            throw new DataLengthException("Message and witness secret lengths do not match.");
        }

        byte[] calcCommitment = calculateCommitment(commitment.getSecret(), message);

        return Arrays.constantTimeAreEqual(commitment.getCommitment(), calcCommitment);
    }

    private byte[] calculateCommitment(byte[] w, byte[] message)
    {
        byte[] commitment = new byte[digest.getDigestSize()];

        digest.update(w, 0, w.length);
        digest.update(message, 0, message.length);
        digest.doFinal(commitment, 0);

        return commitment;
    }
}
