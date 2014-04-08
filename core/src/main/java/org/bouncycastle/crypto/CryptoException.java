package org.bouncycastle.crypto;

/**
 * the foundation class for the hard exceptions thrown by the crypto packages.
 */
public class CryptoException 
    extends Exception
{
    private Throwable cause;

    /**
     * base constructor.
     */
    public CryptoException()
    {
    }

    /**
     * create a CryptoException with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public CryptoException(
        String  message)
    {
        super(message);
    }

    /**
     * Create a CryptoException with the given message and underlying cause.
     *
     * @param message message describing exception.
     * @param cause the throwable that was the underlying cause.
     */
    public CryptoException(
        String  message,
        Throwable cause)
    {
        super(message);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
