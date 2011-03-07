package com.google.bitcoin.bouncycastle.crypto.tls;

/**
 * A queue for bytes.
 * <p/>
 * This file could be more optimized.
 * </p>
 */
public class ByteQueue
{

    /**
     * @return The smallest number which can be written as 2^x which is
     *         bigger than i.
     */
    public static final int nextTwoPow(int i)
    {
        /*
         * This code is based of a lot of code I found on the Internet
         * which mostly referenced a book called "Hacking delight".
         * 
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
    private static final int INITBUFSIZE = 1024;

    /**
     * The buffer where we store our data.
     */
    private byte[] databuf = new byte[ByteQueue.INITBUFSIZE];

    /**
     * How many bytes at the beginning of the buffer are skipped.
     */
    private int skipped = 0;

    /**
     * How many bytes in the buffer are valid data.
     */
    private int available = 0;

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
        if ((available - skip) < len)
        {
            throw new TlsRuntimeException("Not enough data to read");
        }
        if ((buf.length - offset) < len)
        {
            throw new TlsRuntimeException("Buffer size of " + buf.length + " is too small for a read of " + len + " bytes");
        }
        System.arraycopy(databuf, skipped + skip, buf, offset, len);
        return;
    }


    /**
     * Add some data to our buffer.
     *
     * @param data   A byte-array to read data from.
     * @param offset How many bytes to skip at the beginning of the array.
     * @param len    How many bytes to read from the array.
     */
    public void addData(byte[] data, int offset, int len)
    {
        if ((skipped + available + len) > databuf.length)
        {
            byte[] tmp = new byte[ByteQueue.nextTwoPow(data.length)];
            System.arraycopy(databuf, skipped, tmp, 0, available);
            skipped = 0;
            databuf = tmp;
        }
        System.arraycopy(data, offset, databuf, skipped + available, len);
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
            throw new TlsRuntimeException("Cannot remove " + i + " bytes, only got " + available);
        }

        /*
        * Skip the data.
        */
        available -= i;
        skipped += i;

        /*
        * If more than half of our data is skipped, we will move the data
        * in the buffer.
        */
        if (skipped > (databuf.length / 2))
        {
            System.arraycopy(databuf, skipped, databuf, 0, available);
            skipped = 0;
        }
    }

    /**
     * @return The number of bytes which are available in this buffer.
     */
    public int size()
    {
        return available;
    }

}
