package org.bouncycastle.util.io;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

/**
 * An output stream that buffers data to be feed into an encapsulated output stream.
 * <p>
 * The stream zeroes out the internal buffer on each flush.
 * </p>
 */
public class BufferingOutputStream
    extends OutputStream
{
    private final OutputStream other;
    private final byte[] buf;

    private int   bufOff;

    /**
     * Create a buffering stream with the default buffer size (4096).
     *
     * @param other output stream to be wrapped.
     */
    public BufferingOutputStream(OutputStream other)
    {
        this.other = other;
        this.buf = new byte[4096];
    }

    /**
     * Create a buffering stream with a specified buffer size.
     *
     * @param other output stream to be wrapped.
     * @param bufferSize size in bytes for internal buffer.
     */
    public BufferingOutputStream(OutputStream other, int bufferSize)
    {
        this.other = other;
        this.buf = new byte[bufferSize];
    }

    public void write(byte[] bytes, int offset, int len)
        throws IOException
    {
        if (len < buf.length - bufOff)
        {
            System.arraycopy(bytes, offset, buf, bufOff, len);
            bufOff += len;
        }
        else
        {
            int gap = buf.length - bufOff;

            System.arraycopy(bytes, offset, buf, bufOff, gap);
            bufOff += gap;

            flush();

            offset += gap;
            len -= gap;
            while (len >= buf.length)
            {
                other.write(bytes, offset, buf.length);
                offset += buf.length;
                len -= buf.length;
            }

            if (len > 0)
            {
                System.arraycopy(bytes, offset, buf, bufOff, len);
                bufOff += len;
            }
        }
    }

    public void write(int b)
        throws IOException
    {
        buf[bufOff++] = (byte)b;
        if (bufOff == buf.length)
        {
            flush();
        }
    }

    /**
     * Flush the internal buffer to the encapsulated output stream. Zero the buffer contents when done.
     *
     * @throws IOException on error.
     */
    public void flush()
        throws IOException
    {
        other.write(buf, 0, bufOff);
        bufOff = 0;
        Arrays.fill(buf, (byte)0);
    }

    public void close()
        throws IOException
    {
        flush();
        other.close();
    }
}
