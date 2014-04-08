package org.bouncycastle.crypto.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

/**
 * A CipherInputStream is composed of an InputStream and a cipher so that read() methods return data
 * that are read in from the underlying InputStream but have been additionally processed by the
 * Cipher. The cipher must be fully initialized before being used by a CipherInputStream.
 * <p>
 * For example, if the Cipher is initialized for decryption, the
 * CipherInputStream will attempt to read in data and decrypt them,
 * before returning the decrypted data.
 */
public class CipherInputStream
    extends FilterInputStream
{
    private static final int INPUT_BUF_SIZE = 2048;

    private BufferedBlockCipher bufferedBlockCipher;
    private StreamCipher streamCipher;
    private AEADBlockCipher aeadBlockCipher;

    private byte[] buf;
    private final byte[] inBuf = new byte[INPUT_BUF_SIZE];

    private int bufOff;
    private int maxBuf;
    private boolean finalized;

    /**
     * Constructs a CipherInputStream from an InputStream and a
     * BufferedBlockCipher.
     */
    public CipherInputStream(
        InputStream is,
        BufferedBlockCipher cipher)
    {
        super(is);

        this.bufferedBlockCipher = cipher;
    }

    public CipherInputStream(
        InputStream is,
        StreamCipher cipher)
    {
        super(is);

        this.streamCipher = cipher;
    }

    /**
     * Constructs a CipherInputStream from an InputStream and an AEADBlockCipher.
     */
    public CipherInputStream(InputStream is, AEADBlockCipher cipher)
    {
        super(is);

        this.aeadBlockCipher = cipher;
    }

    /**
     * Read data from underlying stream and process with cipher until end of stream or some data is
     * available after cipher processing.
     *
     * @return -1 to indicate end of stream, or the number of bytes (> 0) available.
     */
    private int nextChunk()
        throws IOException
    {
        if (finalized)
        {
            return -1;
        }

        bufOff = 0;
        maxBuf = 0;

        // Keep reading until EOF or cipher processing produces data
        while (maxBuf == 0)
        {
            int read = in.read(inBuf);
            if (read == -1)
            {
                finaliseCipher();
                if (maxBuf == 0)
                {
                    return -1;
                }
                return maxBuf;
            }

            try
            {
                ensureCapacity(read, false);
                if (bufferedBlockCipher != null)
                {
                    maxBuf = bufferedBlockCipher.processBytes(inBuf, 0, read, buf, 0);
                }
                else if (aeadBlockCipher != null)
                {
                    maxBuf = aeadBlockCipher.processBytes(inBuf, 0, read, buf, 0);
                }
                else
                {
                    streamCipher.processBytes(inBuf, 0, read, buf, 0);
                    maxBuf = read;
                }
            }
            catch (Exception e)
            {
                throw new CipherIOException("Error processing stream ", e);
            }
        }
        return maxBuf;
    }

    private void finaliseCipher()
        throws IOException
    {
        try
        {
            finalized = true;
            ensureCapacity(0, true);
            if (bufferedBlockCipher != null)
            {
                maxBuf = bufferedBlockCipher.doFinal(buf, 0);
            }
            else if (aeadBlockCipher != null)
            {
                maxBuf = aeadBlockCipher.doFinal(buf, 0);
            }
            else
            {
                maxBuf = 0; // a stream cipher
            }
        }
        catch (final InvalidCipherTextException e)
        {
            throw new InvalidCipherTextIOException("Error finalising cipher", e);
        }
        catch (Exception e)
        {
            throw new IOException("Error finalising cipher " + e);
        }
    }

    /**
     * Reads data from the underlying stream and processes it with the cipher until the cipher
     * outputs data, and returns the next available byte.
     * <p/>
     * If the underlying stream is exhausted by this call, the cipher will be finalised.
     *
     * @throws IOException if there was an error closing the input stream.
     * @throws InvalidCipherTextIOException if the data read from the stream was invalid ciphertext
     * (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
     */
    public int read()
        throws IOException
    {
        if (bufOff >= maxBuf)
        {
            if (nextChunk() < 0)
            {
                return -1;
            }
        }

        return buf[bufOff++] & 0xff;
    }

    /**
     * Reads data from the underlying stream and processes it with the cipher until the cipher
     * outputs data, and then returns up to <code>b.length</code> bytes in the provided array.
     * <p/>
     * If the underlying stream is exhausted by this call, the cipher will be finalised.
     *
     * @param b the buffer into which the data is read.
     * @return the total number of bytes read into the buffer, or <code>-1</code> if there is no
     *         more data because the end of the stream has been reached.
     * @throws IOException if there was an error closing the input stream.
     * @throws InvalidCipherTextIOException if the data read from the stream was invalid ciphertext
     * (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
     */
    public int read(
        byte[] b)
        throws IOException
    {
        return read(b, 0, b.length);
    }

    /**
     * Reads data from the underlying stream and processes it with the cipher until the cipher
     * outputs data, and then returns up to <code>len</code> bytes in the provided array.
     * <p/>
     * If the underlying stream is exhausted by this call, the cipher will be finalised.
     *
     * @param b   the buffer into which the data is read.
     * @param off the start offset in the destination array <code>b</code>
     * @param len the maximum number of bytes read.
     * @return the total number of bytes read into the buffer, or <code>-1</code> if there is no
     *         more data because the end of the stream has been reached.
     * @throws IOException if there was an error closing the input stream.
     * @throws InvalidCipherTextIOException if the data read from the stream was invalid ciphertext
     * (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
     */
    public int read(
        byte[] b,
        int off,
        int len)
        throws IOException
    {
        if (bufOff >= maxBuf)
        {
            if (nextChunk() < 0)
            {
                return -1;
            }
        }

        int toSupply = Math.min(len, available());
        System.arraycopy(buf, bufOff, b, off, toSupply);
        bufOff += toSupply;
        return toSupply;
    }

    public long skip(
        long n)
        throws IOException
    {
        if (n <= 0)
        {
            return 0;
        }

        int skip = (int)Math.min(n, available());
        bufOff += skip;
        return skip;
    }

    public int available()
        throws IOException
    {
        return maxBuf - bufOff;
    }

    /**
     * Ensure the ciphertext buffer has space sufficient to accept an upcoming output.
     *
     * @param updateSize the size of the pending update.
     * @param finalOutput <code>true</code> iff this the cipher is to be finalised.
     */
    private void ensureCapacity(int updateSize, boolean finalOutput)
    {
        int bufLen = updateSize;
        if (finalOutput)
        {
            if (bufferedBlockCipher != null)
            {
                bufLen = bufferedBlockCipher.getOutputSize(updateSize);
            }
            else if (aeadBlockCipher != null)
            {
                bufLen = aeadBlockCipher.getOutputSize(updateSize);
            }
        }
        else
        {
            if (bufferedBlockCipher != null)
            {
                bufLen = bufferedBlockCipher.getUpdateOutputSize(updateSize);
            }
            else if (aeadBlockCipher != null)
            {
                bufLen = aeadBlockCipher.getUpdateOutputSize(updateSize);
            }
        }

        if ((buf == null) || (buf.length < bufLen))
        {
            buf = new byte[bufLen];
        }
    }

    /**
     * Closes the underlying input stream and finalises the processing of the data by the cipher.
     *
     * @throws IOException if there was an error closing the input stream.
     * @throws InvalidCipherTextIOException if the data read from the stream was invalid ciphertext
     *             (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails).
     */
    public void close()
        throws IOException
    {
        try
        {
            in.close();
        }
        finally
        {
            if (!finalized)
            {
                // Reset the cipher, discarding any data buffered in it
                // Errors in cipher finalisation trump I/O error closing input
                finaliseCipher();
            }
        }
        maxBuf = bufOff = 0;
    }

    public void mark(int readlimit)
    {
    }

    public void reset()
        throws IOException
    {
    }

    public boolean markSupported()
    {
        return false;
    }

}
