package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An OutputStream for an TLS connection.
 */
class TlsOutputStream
    extends OutputStream
{
    private byte[] buf = new byte[1];
    private TlsProtocol handler;

    TlsOutputStream(TlsProtocol handler)
    {
        this.handler = handler;
    }

    public void write(byte buf[], int offset, int len)
        throws IOException
    {
        this.handler.writeData(buf, offset, len);
    }

    public void write(int arg0)
        throws IOException
    {
        buf[0] = (byte)arg0;
        this.write(buf, 0, 1);
    }

    public void close()
        throws IOException
    {
        handler.close();
    }

    public void flush()
        throws IOException
    {
        handler.flush();
    }
}
