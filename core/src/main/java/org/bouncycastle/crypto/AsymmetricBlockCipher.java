package org.bouncycastle.crypto;


/**
 * base interface that a public/private key block cipher needs
 * to conform to.
 */
public interface AsymmetricBlockCipher
{
    /**
     * initialise the cipher.
     *
     * @param forEncryption if true the cipher is initialised for 
     *  encryption, if false for decryption.
     * @param param the key and other data required by the cipher.
     */
    public void init(boolean forEncryption, CipherParameters param);

    /**
     * returns the largest size an input block can be.
     *
     * @return maximum size for an input block.
     */
    public int getInputBlockSize();

    /**
     * returns the maximum size of the block produced by this cipher.
     *
     * @return maximum size of the output block produced by the cipher.
     */
    public int getOutputBlockSize();

    /**
     * process the block of len bytes stored in in from offset inOff.
     *
     * @param in the input data
     * @param inOff offset into the in array where the data starts
     * @param len the length of the block to be processed.
     * @return the resulting byte array of the encryption/decryption process.
     * @exception InvalidCipherTextException data decrypts improperly.
     * @exception DataLengthException the input data is too large for the cipher.
     */
    public byte[] processBlock(byte[] in, int inOff, int len)
        throws InvalidCipherTextException;
}
