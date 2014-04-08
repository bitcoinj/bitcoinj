package org.bouncycastle.crypto;

/**
 * Signer with message recovery.
 */
public interface SignerWithRecovery 
    extends Signer
{
    /**
     * Returns true if the signer has recovered the full message as
     * part of signature verification.
     * 
     * @return true if full message recovered.
     */
    public boolean hasFullMessage();
    
    /**
     * Returns a reference to what message was recovered (if any).
     * 
     * @return full/partial message, null if nothing.
     */
    public byte[] getRecoveredMessage();

    /**
     * Perform an update with the recovered message before adding any other data. This must
     * be the first update method called, and calling it will result in the signer assuming
     * that further calls to update will include message content past what is recoverable.
     *
     * @param signature the signature that we are in the process of verifying.
     * @throws IllegalStateException
     */
    public void updateWithRecoveredMessage(byte[] signature)
        throws InvalidCipherTextException;
}
