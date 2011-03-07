package com.google.bitcoin.bouncycastle.crypto.tls;

import com.google.bitcoin.bouncycastle.crypto.Digest;
import com.google.bitcoin.bouncycastle.crypto.digests.MD5Digest;
import com.google.bitcoin.bouncycastle.crypto.digests.SHA1Digest;
import com.google.bitcoin.bouncycastle.crypto.macs.HMac;
import com.google.bitcoin.bouncycastle.crypto.params.KeyParameter;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Some helper fuctions for MicroTLS.
 */
public class TlsUtils
{
    static byte[] toByteArray(String str)
    {
        char[] chars = str.toCharArray();
        byte[] bytes = new byte[chars.length];

        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }

    protected static void writeUint8(short i, OutputStream os) throws IOException
    {
        os.write(i);
    }

    protected static void writeUint8(short i, byte[] buf, int offset)
    {
        buf[offset] = (byte)i;
    }

    protected static void writeUint16(int i, OutputStream os) throws IOException
    {
        os.write(i >> 8);
        os.write(i);
    }

    protected static void writeUint16(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 8);
        buf[offset + 1] = (byte)i;
    }

    protected static void writeUint24(int i, OutputStream os) throws IOException
    {
        os.write(i >> 16);
        os.write(i >> 8);
        os.write(i);
    }

    protected static void writeUint24(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 16);
        buf[offset + 1] = (byte)(i >> 8);
        buf[offset + 2] = (byte)(i);
    }

    protected static void writeUint32(long i, OutputStream os) throws IOException
    {
        os.write((int)(i >> 24));
        os.write((int)(i >> 16));
        os.write((int)(i >> 8));
        os.write((int)(i));
    }

    protected static void writeUint32(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 24);
        buf[offset + 1] = (byte)(i >> 16);
        buf[offset + 2] = (byte)(i >> 8);
        buf[offset + 3] = (byte)(i);
    }

    protected static void writeUint64(long i, OutputStream os) throws IOException
    {
        os.write((int)(i >> 56));
        os.write((int)(i >> 48));
        os.write((int)(i >> 40));
        os.write((int)(i >> 32));
        os.write((int)(i >> 24));
        os.write((int)(i >> 16));
        os.write((int)(i >> 8));
        os.write((int)(i));
    }


    protected static void writeUint64(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 56);
        buf[offset + 1] = (byte)(i >> 48);
        buf[offset + 2] = (byte)(i >> 40);
        buf[offset + 3] = (byte)(i >> 32);
        buf[offset + 4] = (byte)(i >> 24);
        buf[offset + 5] = (byte)(i >> 16);
        buf[offset + 6] = (byte)(i >> 8);
        buf[offset + 7] = (byte)(i);
    }

    protected static void writeOpaque8(byte[] buf, OutputStream os) throws IOException
    {
        writeUint8((short)buf.length, os);
        os.write(buf);
    }

    protected static void writeOpaque16(byte[] buf, OutputStream os) throws IOException
    {
        writeUint16(buf.length, os);
        os.write(buf);
    }

    protected static short readUint8(InputStream is) throws IOException
    {
        int i = is.read();
        if (i == -1)
        {
            throw new EOFException();
        }
        return (short)i;
    }

    protected static int readUint16(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        if ((i1 | i2) < 0)
        {
            throw new EOFException();
        }
        return i1 << 8 | i2;
    }

    protected static int readUint24(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        int i3 = is.read();
        if ((i1 | i2 | i3) < 0)
        {
            throw new EOFException();
        }
        return (i1 << 16) | (i2 << 8) | i3;
    }

    protected static long readUint32(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        int i3 = is.read();
        int i4 = is.read();
        if ((i1 | i2 | i3 | i4) < 0)
        {
            throw new EOFException();
        }
        return (((long)i1) << 24) | (((long)i2) << 16) | (((long)i3) << 8) | ((long)i4);
    }

    protected static void readFully(byte[] buf, InputStream is) throws IOException
    {
        int read = 0;
        int i = 0;
        while (read != buf.length)
        {
            i = is.read(buf, read, (buf.length - read));
            if (i == -1)
            {
                throw new EOFException();
            }
            read += i;
        }
    }

    protected static byte[] readOpaque8(InputStream is) throws IOException
    {
        short length = readUint8(is);
        byte[] value = new byte[length];
        readFully(value, is);
        return value;
    }

    protected static byte[] readOpaque16(InputStream is) throws IOException
    {
        int length = readUint16(is);
        byte[] value = new byte[length];
        readFully(value, is);
        return value;
    }

    protected static void checkVersion(byte[] readVersion, TlsProtocolHandler handler) throws IOException
    {
        if ((readVersion[0] != 3) || (readVersion[1] != 1))
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_protocol_version);
        }
    }

    protected static void checkVersion(InputStream is, TlsProtocolHandler handler) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        if ((i1 != 3) || (i2 != 1))
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_protocol_version);
        }
    }

    protected static void writeVersion(OutputStream os) throws IOException
    {
        os.write(3);
        os.write(1);
    }

    private static void hmac_hash(Digest digest, byte[] secret, byte[] seed, byte[] out)
    {
        HMac mac = new HMac(digest);
        KeyParameter param = new KeyParameter(secret);
        byte[] a = seed;
        int size = digest.getDigestSize();
        int iterations = (out.length + size - 1) / size;
        byte[] buf = new byte[mac.getMacSize()];
        byte[] buf2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.init(param);
            mac.update(a, 0, a.length);
            mac.doFinal(buf, 0);
            a = buf;
            mac.init(param);
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(buf2, 0);
            System.arraycopy(buf2, 0, out, (size * i), Math.min(size, out.length - (size * i)));
        }
    }

    protected static void PRF(byte[] secret, byte[] label, byte[] seed, byte[] buf)
    {
        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] ls = new byte[label.length + seed.length];
        System.arraycopy(label, 0, ls, 0, label.length);
        System.arraycopy(seed, 0, ls, label.length, seed.length);

        byte[] prf = new byte[buf.length];
        hmac_hash(new MD5Digest(), s1, ls, prf);
        hmac_hash(new SHA1Digest(), s2, ls, buf);
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] ^= prf[i];
        }
    }

}
