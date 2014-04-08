package org.bouncycastle.crypto.prng;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * A secure random that returns pre-seeded data to calls of nextBytes() or generateSeed().
 */
public class FixedSecureRandom
    extends SecureRandom
{
    private byte[]       _data;
    
    private int          _index;
    private int          _intPad;
    
    public FixedSecureRandom(byte[] value)
    {
        this(false, new byte[][] { value });
    }
    
    public FixedSecureRandom(
        byte[][] values)
    {
        this(false, values);
    }
    
    /**
     * Pad the data on integer boundaries. This is necessary for the classpath project's BigInteger
     * implementation.
     */
    public FixedSecureRandom(
        boolean intPad,
        byte[] value)
    {
        this(intPad, new byte[][] { value });
    }
    
    /**
     * Pad the data on integer boundaries. This is necessary for the classpath project's BigInteger
     * implementation.
     */
    public FixedSecureRandom(
        boolean intPad,
        byte[][] values)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        for (int i = 0; i != values.length; i++)
        {
            try
            {
                bOut.write(values[i]);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("can't save value array.");
            }
        }
        
        _data = bOut.toByteArray();
        
        if (intPad)
        {
            _intPad = _data.length % 4;
        }
    }

    public void nextBytes(byte[] bytes)
    {
        System.arraycopy(_data, _index, bytes, 0, bytes.length);
        
        _index += bytes.length;
    }

    public byte[] generateSeed(int numBytes)
    {
        byte[] bytes = new byte[numBytes];

        this.nextBytes(bytes);

        return bytes;
    }

    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
    public int nextInt()
    {
        int val = 0;
        
        val |= nextValue() << 24;
        val |= nextValue() << 16;
        
        if (_intPad == 2)
        {
            _intPad--;
        }
        else
        {
            val |= nextValue() << 8;
        }
        
        if (_intPad == 1)
        {
            _intPad--;
        }
        else
        {
            val |= nextValue();
        }
        
        return val;
    }
    
    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
    public long nextLong()
    {
        long val = 0;
        
        val |= (long)nextValue() << 56;
        val |= (long)nextValue() << 48;
        val |= (long)nextValue() << 40;
        val |= (long)nextValue() << 32;
        val |= (long)nextValue() << 24;
        val |= (long)nextValue() << 16;
        val |= (long)nextValue() << 8;
        val |= (long)nextValue();
        
        return val;
    }

    public boolean isExhausted()
    {
        return _index == _data.length;
    }

    private int nextValue()
    {
        return _data[_index++] & 0xff;
    }
}
