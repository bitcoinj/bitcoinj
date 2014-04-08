package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.CipherParameters;

public interface MessageSigner
{
    /**
     * initialise the signer for signature generation or signature
     * verification.
     *
     * @param forSigning true if we are generating a signature, false
     *                   otherwise.
     * @param param      key parameters for signature generation.
     */
    public void init(boolean forSigning, CipherParameters param);

    /**
     * sign the passed in message (usually the output of a hash function).
     *
     * @param message the message to be signed.
     * @return the signature of the message
     */
    public byte[] generateSignature(byte[] message);

    /**
     * verify the message message against the signature values r and s.
     *
     * @param message the message that was supposed to have been signed.
     * @param signature the signature of the message
     */
    public boolean verifySignature(byte[] message, byte[] signature);
}
