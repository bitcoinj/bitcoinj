package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class UDPTransport
    implements DatagramTransport
{
    protected final static int MIN_IP_OVERHEAD = 20;
    protected final static int MAX_IP_OVERHEAD = MIN_IP_OVERHEAD + 64;
    protected final static int UDP_OVERHEAD = 8;

    protected final DatagramSocket socket;
    protected final int receiveLimit, sendLimit;

    public UDPTransport(DatagramSocket socket, int mtu)
        throws IOException
    {
        if (!socket.isBound() || !socket.isConnected())
        {
            throw new IllegalArgumentException("'socket' must be bound and connected");
        }

        this.socket = socket;

        // NOTE: As of JDK 1.6, can use NetworkInterface.getMTU

        this.receiveLimit = mtu - MIN_IP_OVERHEAD - UDP_OVERHEAD;
        this.sendLimit = mtu - MAX_IP_OVERHEAD - UDP_OVERHEAD;
    }

    public int getReceiveLimit()
    {
        return receiveLimit;
    }

    public int getSendLimit()
    {
        // TODO[DTLS] Implement Path-MTU discovery?
        return sendLimit;
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        socket.setSoTimeout(waitMillis);
        DatagramPacket packet = new DatagramPacket(buf, off, len);
        socket.receive(packet);
        return packet.getLength();
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        if (len > getSendLimit())
        {
            /*
             * RFC 4347 4.1.1. "If the application attempts to send a record larger than the MTU,
             * the DTLS implementation SHOULD generate an error, thus avoiding sending a packet
             * which will be fragmented."
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        DatagramPacket packet = new DatagramPacket(buf, off, len);
        socket.send(packet);
    }

    public void close()
        throws IOException
    {
        socket.close();
    }
}
