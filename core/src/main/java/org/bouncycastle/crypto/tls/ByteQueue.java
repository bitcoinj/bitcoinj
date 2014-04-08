package org.bouncycastle.crypto.tls;

/**
 * A queue for bytes. This file could be more optimized.
 */
public class ByteQueue
{
    /**
     * @return The smallest number which can be written as 2^x which is bigger than i.
     */
    public static final int nextTwoPow(int i)
    {
        /*
         * This code is based of a lot of code I found on the Internet which mostly
         * referenced a book called "Hacking delight".
         */
        i |= (i >> 1);
        i |= (i >> 2);
        i |= (i >> 4);
        i |= (i >> 8);
        i |= (i >> 16);
        return i + 1;
    }

    /**
     * The initial size for our buffer.
     */
    private static final int DEFAULT_CAPACITY = 1024;

    /**
     * The buffer where we store our data.
     */
    private byte[] databuf;;

    /**
     * How many bytes at the beginning of the buffer are skipped.
     */
    private int skipped = 0;

    /**
     * How many bytes in the buffer are valid data.
     */
    private int available = 0;

    public ByteQueue()
    {
        this(DEFAULT_CAPACITY);
    }

    public ByteQueue(int capacity)
    {
        databuf = new byte[capacity];
    }

    /**
     * Read data from the buffer.
     *
     * @param buf    The buffer where the read data will be copied to.
     * @param offset How many bytes to skip at the beginning of buf.
     * @param len    How many bytes to read at all.
     * @param skip   How many bytes from our data to skip.
     */
    public void read(byte[] buf, int offset, int len, int skip)
    {
        if ((buf.length - offset) < len)
        {
            throw new IllegalArgumentException("Buffer size of " + buf.length
                + " is too small for a read of " + len + " bytes");
        }
        if ((available - skip) < len)
        {
            throw new IllegalStateException("Not enough data to read");
        }
        System.arraycopy(databuf, skipped + skip, buf, offset, len);
    }

    /**
     * Add some data to our buffer.
     *
     * @param buf A byte-array to read data from.
     * @param off How many bytes to skip at the beginning of the array.
     * @param len How many bytes to read from the array.
     */
    public void addData(byte[] buf, int off, int len)
    {
        if ((skipped + available + len) > databuf.length)
        {
            int desiredSize = ByteQueue.nextTwoPow(available + len);
            if (desiredSize > databuf.length)
            {
                byte[] tmp = new byte[desiredSize];
                System.arraycopy(databuf, skipped, tmp, 0, available);
                databuf = tmp;
            }
            else
            {
                System.arraycopy(databuf, skipped, databuf, 0, available);
            }
            skipped = 0;
        }

        System.arraycopy(buf, off, databuf, skipped + available, len);
        available += len;
    }

    /**
     * Remove some bytes from our data from the beginning.
     *
     * @param i How many bytes to remove.
     */
    public void removeData(int i)
    {
        if (i > available)
        {
            throw new IllegalStateException("Cannot remove " + i + " bytes, only got " + available);
        }

        /*
         * Skip the data.
         */
        available -= i;
        skipped += i;
    }

    /**
     * Remove data from the buffer.
     *
     * @param buf The buffer where the removed data will be copied to.
     * @param off How many bytes to skip at the beginning of buf.
     * @param len How many bytes to read at all.
     * @param skip How many bytes from our data to skip.
     */
    public void removeData(byte[] buf, int off, int len, int skip)
    {
        read(buf, off, len, skip);
        removeData(skip + len);
    }

    public byte[] removeData(int len, int skip)
    {
        byte[] buf = new byte[len];
        removeData(buf, 0, len, skip);
        return buf;
    }

    /**
     * @return The number of bytes which are available in this buffer.
     */
    public int size()
    {
        return available;
    }
}
