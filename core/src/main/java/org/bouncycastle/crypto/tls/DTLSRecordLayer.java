package org.bouncycastle.crypto.tls;

import java.io.IOException;

class DTLSRecordLayer
    implements DatagramTransport
{
    private static final int RECORD_HEADER_LENGTH = 13;
    private static final int MAX_FRAGMENT_LENGTH = 1 << 14;
    private static final long TCP_MSL = 1000L * 60 * 2;
    private static final long RETRANSMIT_TIMEOUT = TCP_MSL * 2;

    private final DatagramTransport transport;
    private final TlsContext context;
    private final TlsPeer peer;

    private final ByteQueue recordQueue = new ByteQueue();

    private volatile boolean closed = false;
    private volatile boolean failed = false;
    private volatile ProtocolVersion discoveredPeerVersion = null;
    private volatile boolean inHandshake;
    private volatile int plaintextLimit;
    private DTLSEpoch currentEpoch, pendingEpoch;
    private DTLSEpoch readEpoch, writeEpoch;

    private DTLSHandshakeRetransmit retransmit = null;
    private DTLSEpoch retransmitEpoch = null;
    private long retransmitExpiry = 0;

    DTLSRecordLayer(DatagramTransport transport, TlsContext context, TlsPeer peer, short contentType)
    {
        this.transport = transport;
        this.context = context;
        this.peer = peer;

        this.inHandshake = true;

        this.currentEpoch = new DTLSEpoch(0, new TlsNullCipher(context));
        this.pendingEpoch = null;
        this.readEpoch = currentEpoch;
        this.writeEpoch = currentEpoch;

        setPlaintextLimit(MAX_FRAGMENT_LENGTH);
    }

    void setPlaintextLimit(int plaintextLimit)
    {
        this.plaintextLimit = plaintextLimit;
    }

    ProtocolVersion getDiscoveredPeerVersion()
    {
        return discoveredPeerVersion;
    }

    ProtocolVersion resetDiscoveredPeerVersion()
    {
        ProtocolVersion result = discoveredPeerVersion; 
        discoveredPeerVersion = null;
        return result;
    }

    void initPendingEpoch(TlsCipher pendingCipher)
    {
        if (pendingEpoch != null)
        {
            throw new IllegalStateException();
        }

        /*
         * TODO "In order to ensure that any given sequence/epoch pair is unique, implementations
         * MUST NOT allow the same epoch value to be reused within two times the TCP maximum segment
         * lifetime."
         */

        // TODO Check for overflow
        this.pendingEpoch = new DTLSEpoch(writeEpoch.getEpoch() + 1, pendingCipher);
    }

    void handshakeSuccessful(DTLSHandshakeRetransmit retransmit)
    {
        if (readEpoch == currentEpoch || writeEpoch == currentEpoch)
        {
            // TODO
            throw new IllegalStateException();
        }

        if (retransmit != null)
        {
            this.retransmit = retransmit;
            this.retransmitEpoch = currentEpoch;
            this.retransmitExpiry = System.currentTimeMillis() + RETRANSMIT_TIMEOUT;
        }

        this.inHandshake = false;
        this.currentEpoch = pendingEpoch;
        this.pendingEpoch = null;
    }

    void resetWriteEpoch()
    {
        if (retransmitEpoch != null)
        {
            this.writeEpoch = retransmitEpoch;
        }
        else
        {
            this.writeEpoch = currentEpoch;
        }
    }

    public int getReceiveLimit()
        throws IOException
    {
        return Math.min(this.plaintextLimit,
            readEpoch.getCipher().getPlaintextLimit(transport.getReceiveLimit() - RECORD_HEADER_LENGTH));
    }

    public int getSendLimit()
        throws IOException
    {
        return Math.min(this.plaintextLimit,
            writeEpoch.getCipher().getPlaintextLimit(transport.getSendLimit() - RECORD_HEADER_LENGTH));
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        byte[] record = null;

        for (;;)
        {
            int receiveLimit = Math.min(len, getReceiveLimit()) + RECORD_HEADER_LENGTH;
            if (record == null || record.length < receiveLimit)
            {
                record = new byte[receiveLimit];
            }

            try
            {
                if (retransmit != null && System.currentTimeMillis() > retransmitExpiry)
                {
                    retransmit = null;
                    retransmitEpoch = null;
                }

                int received = receiveRecord(record, 0, receiveLimit, waitMillis);
                if (received < 0)
                {
                    return received;
                }
                if (received < RECORD_HEADER_LENGTH)
                {
                    continue;
                }
                int length = TlsUtils.readUint16(record, 11);
                if (received != (length + RECORD_HEADER_LENGTH))
                {
                    continue;
                }

                short type = TlsUtils.readUint8(record, 0);

                // TODO Support user-specified custom protocols?
                switch (type)
                {
                case ContentType.alert:
                case ContentType.application_data:
                case ContentType.change_cipher_spec:
                case ContentType.handshake:
                case ContentType.heartbeat:
                    break;
                default:
                    // TODO Exception?
                    continue;
                }

                int epoch = TlsUtils.readUint16(record, 3);

                DTLSEpoch recordEpoch = null;
                if (epoch == readEpoch.getEpoch())
                {
                    recordEpoch = readEpoch;
                }
                else if (type == ContentType.handshake && retransmitEpoch != null
                    && epoch == retransmitEpoch.getEpoch())
                {
                    recordEpoch = retransmitEpoch;
                }

                if (recordEpoch == null)
                {
                    continue;
                }

                long seq = TlsUtils.readUint48(record, 5);
                if (recordEpoch.getReplayWindow().shouldDiscard(seq))
                {
                    continue;
                }

                ProtocolVersion version = TlsUtils.readVersion(record, 1);
                if (discoveredPeerVersion != null && !discoveredPeerVersion.equals(version))
                {
                    continue;
                }

                byte[] plaintext = recordEpoch.getCipher().decodeCiphertext(
                    getMacSequenceNumber(recordEpoch.getEpoch(), seq), type, record, RECORD_HEADER_LENGTH,
                    received - RECORD_HEADER_LENGTH);

                recordEpoch.getReplayWindow().reportAuthenticated(seq);

                if (plaintext.length > this.plaintextLimit)
                {
                    continue;
                }

                if (discoveredPeerVersion == null)
                {
                    discoveredPeerVersion = version;
                }

                switch (type)
                {
                case ContentType.alert:
                {
                    if (plaintext.length == 2)
                    {
                        short alertLevel = plaintext[0];
                        short alertDescription = plaintext[1];

                        peer.notifyAlertReceived(alertLevel, alertDescription);

                        if (alertLevel == AlertLevel.fatal)
                        {
                            fail(alertDescription);
                            throw new TlsFatalAlert(alertDescription);
                        }

                        // TODO Can close_notify be a fatal alert?
                        if (alertDescription == AlertDescription.close_notify)
                        {
                            closeTransport();
                        }
                    }
                    else
                    {
                        // TODO What exception?
                    }

                    continue;
                }
                case ContentType.application_data:
                {
                    if (inHandshake)
                    {
                        // TODO Consider buffering application data for new epoch that arrives
                        // out-of-order with the Finished message
                        continue;
                    }
                    break;
                }
                case ContentType.change_cipher_spec:
                {
                    // Implicitly receive change_cipher_spec and change to pending cipher state

                    for (int i = 0; i < plaintext.length; ++i)
                    {
                        short message = TlsUtils.readUint8(plaintext, i);
                        if (message != ChangeCipherSpec.change_cipher_spec)
                        {
                            continue;
                        }

                        if (pendingEpoch != null)
                        {
                            readEpoch = pendingEpoch;
                        }
                    }

                    continue;
                }
                case ContentType.handshake:
                {
                    if (!inHandshake)
                    {
                        if (retransmit != null)
                        {
                            retransmit.receivedHandshakeRecord(epoch, plaintext, 0, plaintext.length);
                        }

                        // TODO Consider support for HelloRequest
                        continue;
                    }
                    break;
                }
                case ContentType.heartbeat:
                {
                    // TODO[RFC 6520]
                    continue;
                }
                }

                /*
                 * NOTE: If we receive any non-handshake data in the new epoch implies the peer has
                 * received our final flight.
                 */
                if (!inHandshake && retransmit != null)
                {
                    this.retransmit = null;
                    this.retransmitEpoch = null;
                }

                System.arraycopy(plaintext, 0, buf, off, plaintext.length);
                return plaintext.length;
            }
            catch (IOException e)
            {
                // NOTE: Assume this is a timeout for the moment
                throw e;
            }
        }
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        short contentType = ContentType.application_data;

        if (this.inHandshake || this.writeEpoch == this.retransmitEpoch)
        {
            contentType = ContentType.handshake;

            short handshakeType = TlsUtils.readUint8(buf, off);
            if (handshakeType == HandshakeType.finished)
            {
                DTLSEpoch nextEpoch = null;
                if (this.inHandshake)
                {
                    nextEpoch = pendingEpoch;
                }
                else if (this.writeEpoch == this.retransmitEpoch)
                {
                    nextEpoch = currentEpoch;
                }

                if (nextEpoch == null)
                {
                    // TODO
                    throw new IllegalStateException();
                }

                // Implicitly send change_cipher_spec and change to pending cipher state

                // TODO Send change_cipher_spec and finished records in single datagram?
                byte[] data = new byte[]{ 1 };
                sendRecord(ContentType.change_cipher_spec, data, 0, data.length);

                writeEpoch = nextEpoch;
            }
        }

        sendRecord(contentType, buf, off, len);
    }

    public void close()
        throws IOException
    {
        if (!closed)
        {
            if (inHandshake)
            {
                warn(AlertDescription.user_canceled, "User canceled handshake");
            }
            closeTransport();
        }
    }

    void fail(short alertDescription)
    {
        if (!closed)
        {
            try
            {
                raiseAlert(AlertLevel.fatal, alertDescription, null, null);
            }
            catch (Exception e)
            {
                // Ignore
            }

            failed = true;

            closeTransport();
        }
    }

    void warn(short alertDescription, String message)
        throws IOException
    {
        raiseAlert(AlertLevel.warning, alertDescription, message, null);
    }

    private void closeTransport()
    {
        if (!closed)
        {
            /*
             * RFC 5246 7.2.1. Unless some other fatal alert has been transmitted, each party is
             * required to send a close_notify alert before closing the write side of the
             * connection. The other party MUST respond with a close_notify alert of its own and
             * close down the connection immediately, discarding any pending writes.
             */

            try
            {
                if (!failed)
                {
                    warn(AlertDescription.close_notify, null);
                }
                transport.close();
            }
            catch (Exception e)
            {
                // Ignore
            }

            closed = true;
        }
    }

    private void raiseAlert(short alertLevel, short alertDescription, String message, Exception cause)
        throws IOException
    {
        peer.notifyAlertRaised(alertLevel, alertDescription, message, cause);

        byte[] error = new byte[2];
        error[0] = (byte)alertLevel;
        error[1] = (byte)alertDescription;

        sendRecord(ContentType.alert, error, 0, 2);
    }

    private int receiveRecord(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        if (recordQueue.size() > 0)
        {
            int length = 0;
            if (recordQueue.size() >= RECORD_HEADER_LENGTH)
            {
                byte[] lengthBytes = new byte[2];
                recordQueue.read(lengthBytes, 0, 2, 11);
                length = TlsUtils.readUint16(lengthBytes, 0);
            }

            int received = Math.min(recordQueue.size(), RECORD_HEADER_LENGTH + length);
            recordQueue.removeData(buf, off, received, 0);
            return received;
        }

        int received = transport.receive(buf, off, len, waitMillis);
        if (received >= RECORD_HEADER_LENGTH)
        {
            int fragmentLength = TlsUtils.readUint16(buf, off + 11);
            int recordLength = RECORD_HEADER_LENGTH + fragmentLength;
            if (received > recordLength)
            {
                recordQueue.addData(buf, off + recordLength, received - recordLength);
                received = recordLength;
            }
        }

        return received;
    }

    private void sendRecord(short contentType, byte[] buf, int off, int len)
        throws IOException
    {
        if (len > this.plaintextLimit)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /*
         * RFC 5264 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
         * or ChangeCipherSpec content types.
         */
        if (len < 1 && contentType != ContentType.application_data)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int recordEpoch = writeEpoch.getEpoch();
        long recordSequenceNumber = writeEpoch.allocateSequenceNumber();

        byte[] ciphertext = writeEpoch.getCipher().encodePlaintext(
            getMacSequenceNumber(recordEpoch, recordSequenceNumber), contentType, buf, off, len);

        // TODO Check the ciphertext length?

        byte[] record = new byte[ciphertext.length + RECORD_HEADER_LENGTH];
        TlsUtils.writeUint8(contentType, record, 0);
        ProtocolVersion version = discoveredPeerVersion != null ? discoveredPeerVersion : context.getClientVersion();
        TlsUtils.writeVersion(version, record, 1);
        TlsUtils.writeUint16(recordEpoch, record, 3);
        TlsUtils.writeUint48(recordSequenceNumber, record, 5);
        TlsUtils.writeUint16(ciphertext.length, record, 11);
        System.arraycopy(ciphertext, 0, record, RECORD_HEADER_LENGTH, ciphertext.length);

        transport.send(record, 0, record.length);
    }

    private static long getMacSequenceNumber(int epoch, long sequence_number)
    {
        return ((epoch & 0xFFFFFFFFL) << 48) | sequence_number;
    }
}
