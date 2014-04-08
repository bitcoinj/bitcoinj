package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface DatagramTransport
{
    int getReceiveLimit()
        throws IOException;

    int getSendLimit()
        throws IOException;

    int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException;

    void send(byte[] buf, int off, int len)
        throws IOException;

    void close()
        throws IOException;
}
