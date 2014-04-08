package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Times;

/**
 * An implementation of all high level protocols in TLS 1.0/1.1.
 */
public abstract class TlsProtocol
{
    protected static final Integer EXT_RenegotiationInfo = Integers.valueOf(ExtensionType.renegotiation_info);
    protected static final Integer EXT_SessionTicket = Integers.valueOf(ExtensionType.session_ticket);

    private static final String TLS_ERROR_MESSAGE = "Internal TLS error, this could be an attack";

    /*
     * Our Connection states
     */
    protected static final short CS_START = 0;
    protected static final short CS_CLIENT_HELLO = 1;
    protected static final short CS_SERVER_HELLO = 2;
    protected static final short CS_SERVER_SUPPLEMENTAL_DATA = 3;
    protected static final short CS_SERVER_CERTIFICATE = 4;
    protected static final short CS_CERTIFICATE_STATUS = 5;
    protected static final short CS_SERVER_KEY_EXCHANGE = 6;
    protected static final short CS_CERTIFICATE_REQUEST = 7;
    protected static final short CS_SERVER_HELLO_DONE = 8;
    protected static final short CS_CLIENT_SUPPLEMENTAL_DATA = 9;
    protected static final short CS_CLIENT_CERTIFICATE = 10;
    protected static final short CS_CLIENT_KEY_EXCHANGE = 11;
    protected static final short CS_CERTIFICATE_VERIFY = 12;
    protected static final short CS_CLIENT_FINISHED = 13;
    protected static final short CS_SERVER_SESSION_TICKET = 14;
    protected static final short CS_SERVER_FINISHED = 15;
    protected static final short CS_END = 16;

    /*
     * Queues for data from some protocols.
     */
    private ByteQueue applicationDataQueue = new ByteQueue();
    private ByteQueue alertQueue = new ByteQueue(2);
    private ByteQueue handshakeQueue = new ByteQueue();

    /*
     * The Record Stream we use
     */
    protected RecordStream recordStream;
    protected SecureRandom secureRandom;

    private TlsInputStream tlsInputStream = null;
    private TlsOutputStream tlsOutputStream = null;

    private volatile boolean closed = false;
    private volatile boolean failedWithError = false;
    private volatile boolean appDataReady = false;
    private volatile boolean splitApplicationDataRecords = true;
    private byte[] expected_verify_data = null;

    protected TlsSession tlsSession = null;
    protected SessionParameters sessionParameters = null;
    protected SecurityParameters securityParameters = null;
    protected Certificate peerCertificate = null;

    protected int[] offeredCipherSuites = null;
    protected short[] offeredCompressionMethods = null;
    protected Hashtable clientExtensions = null;
    protected Hashtable serverExtensions = null;

    protected short connection_state = CS_START;
    protected boolean resumedSession = false;
    protected boolean receivedChangeCipherSpec = false;
    protected boolean secure_renegotiation = false;
    protected boolean allowCertificateStatus = false;
    protected boolean expectSessionTicket = false;

    public TlsProtocol(InputStream input, OutputStream output, SecureRandom secureRandom)
    {
        this.recordStream = new RecordStream(this, input, output);
        this.secureRandom = secureRandom;
    }

    protected abstract AbstractTlsContext getContext();

    protected abstract TlsPeer getPeer();

    protected void handleChangeCipherSpecMessage() throws IOException
    {
    }

    protected abstract void handleHandshakeMessage(short type, byte[] buf)
        throws IOException;

    protected void handleWarningMessage(short description)
        throws IOException
    {
    }

    protected void cleanupHandshake()
    {
        if (this.expected_verify_data != null)
        {
            Arrays.fill(this.expected_verify_data, (byte)0);
            this.expected_verify_data = null;
        }

        this.securityParameters.clear();
        this.peerCertificate = null;

        this.offeredCipherSuites = null;
        this.offeredCompressionMethods = null;
        this.clientExtensions = null;
        this.serverExtensions = null;

        this.resumedSession = false;
        this.receivedChangeCipherSpec = false;
        this.secure_renegotiation = false;
        this.allowCertificateStatus = false;
        this.expectSessionTicket = false;
    }

    protected void completeHandshake()
        throws IOException
    {
        try
        {
            /*
             * We will now read data, until we have completed the handshake.
             */
            while (this.connection_state != CS_END)
            {
                if (this.closed)
                {
                    // TODO What kind of exception/alert?
                }

                safeReadRecord();
            }

            this.recordStream.finaliseHandshake();

            this.splitApplicationDataRecords = !TlsUtils.isTLSv11(getContext());

            /*
             * If this was an initial handshake, we are now ready to send and receive application data.
             */
            if (!appDataReady)
            {
                this.appDataReady = true;

                this.tlsInputStream = new TlsInputStream(this);
                this.tlsOutputStream = new TlsOutputStream(this);
            }

            if (this.tlsSession != null)
            {
                if (this.sessionParameters == null)
                {
                    this.sessionParameters = new SessionParameters.Builder()
                        .setCipherSuite(this.securityParameters.cipherSuite)
                        .setCompressionAlgorithm(this.securityParameters.compressionAlgorithm)
                        .setMasterSecret(this.securityParameters.masterSecret)
                        .setPeerCertificate(this.peerCertificate)
                        // TODO Consider filtering extensions that aren't relevant to resumed sessions
                        .setServerExtensions(this.serverExtensions)
                        .build();

                    this.tlsSession = new TlsSessionImpl(this.tlsSession.getSessionID(), this.sessionParameters);
                }

                getContext().setResumableSession(this.tlsSession);
            }

            getPeer().notifyHandshakeComplete();
        }
        finally
        {
            cleanupHandshake();
        }
    }

    protected void processRecord(short protocol, byte[] buf, int offset, int len)
        throws IOException
    {
        /*
         * Have a look at the protocol type, and add it to the correct queue.
         */
        switch (protocol)
        {
        case ContentType.alert:
        {
            alertQueue.addData(buf, offset, len);
            processAlert();
            break;
        }
        case ContentType.application_data:
        {
            if (!appDataReady)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            applicationDataQueue.addData(buf, offset, len);
            processApplicationData();
            break;
        }
        case ContentType.change_cipher_spec:
        {
            processChangeCipherSpec(buf, offset, len);
            break;
        }
        case ContentType.handshake:
        {
            handshakeQueue.addData(buf, offset, len);
            processHandshake();
            break;
        }
        case ContentType.heartbeat:
        {
            // TODO[RFC 6520]
        }
        default:
            /*
             * Uh, we don't know this protocol.
             * 
             * RFC2246 defines on page 13, that we should ignore this.
             */
        }
    }

    private void processHandshake()
        throws IOException
    {
        boolean read;
        do
        {
            read = false;
            /*
             * We need the first 4 bytes, they contain type and length of the message.
             */
            if (handshakeQueue.size() >= 4)
            {
                byte[] beginning = new byte[4];
                handshakeQueue.read(beginning, 0, 4, 0);
                ByteArrayInputStream bis = new ByteArrayInputStream(beginning);
                short type = TlsUtils.readUint8(bis);
                int len = TlsUtils.readUint24(bis);

                /*
                 * Check if we have enough bytes in the buffer to read the full message.
                 */
                if (handshakeQueue.size() >= (len + 4))
                {
                    /*
                     * Read the message.
                     */
                    byte[] buf = handshakeQueue.removeData(len, 4);

                    /*
                     * RFC 2246 7.4.9. The value handshake_messages includes all handshake messages
                     * starting at client hello up to, but not including, this finished message.
                     * [..] Note: [Also,] Hello Request messages are omitted from handshake hashes.
                     */
                    switch (type)
                    {
                    case HandshakeType.hello_request:
                        break;
                    case HandshakeType.finished:
                    {
                        if (this.expected_verify_data == null)
                        {
                            this.expected_verify_data = createVerifyData(!getContext().isServer());
                        }

                        // NB: Fall through to next case label
                    }
                    default:
                        recordStream.updateHandshakeData(beginning, 0, 4);
                        recordStream.updateHandshakeData(buf, 0, len);
                        break;
                    }

                    /*
                     * Now, parse the message.
                     */
                    handleHandshakeMessage(type, buf);
                    read = true;
                }
            }
        }
        while (read);
    }

    private void processApplicationData()
    {
        /*
         * There is nothing we need to do here.
         * 
         * This function could be used for callbacks when application data arrives in the future.
         */
    }

    private void processAlert()
        throws IOException
    {
        while (alertQueue.size() >= 2)
        {
            /*
             * An alert is always 2 bytes. Read the alert.
             */
            byte[] tmp = alertQueue.removeData(2, 0);
            short level = tmp[0];
            short description = tmp[1];

            getPeer().notifyAlertReceived(level, description);

            if (level == AlertLevel.fatal)
            {
                /*
                 * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
                 * without proper close_notify messages with level equal to warning.
                 */
                invalidateSession();

                this.failedWithError = true;
                this.closed = true;

                recordStream.safeClose();

                throw new IOException(TLS_ERROR_MESSAGE);
            }
            else
            {

                /*
                 * RFC 5246 7.2.1. The other party MUST respond with a close_notify alert of its own
                 * and close down the connection immediately, discarding any pending writes.
                 */
                // TODO Can close_notify be a fatal alert?
                if (description == AlertDescription.close_notify)
                {
                    handleClose(false);
                }

                /*
                 * If it is just a warning, we continue.
                 */
                handleWarningMessage(description);
            }
        }
    }

    /**
     * This method is called, when a change cipher spec message is received.
     *
     * @throws IOException If the message has an invalid content or the handshake is not in the correct
     * state.
     */
    private void processChangeCipherSpec(byte[] buf, int off, int len)
        throws IOException
    {
        for (int i = 0; i < len; ++i)
        {
            short message = TlsUtils.readUint8(buf, off + i);

            if (message != ChangeCipherSpec.change_cipher_spec)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            if (this.receivedChangeCipherSpec)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.receivedChangeCipherSpec = true;

            recordStream.receivedReadCipherSpec();
    
            handleChangeCipherSpecMessage();
        }
    }

    /**
     * Read data from the network. The method will return immediately, if there is still some data
     * left in the buffer, or block until some application data has been read from the network.
     *
     * @param buf    The buffer where the data will be copied to.
     * @param offset The position where the data will be placed in the buffer.
     * @param len    The maximum number of bytes to read.
     * @return The number of bytes read.
     * @throws IOException If something goes wrong during reading data.
     */
    protected int readApplicationData(byte[] buf, int offset, int len)
        throws IOException
    {
        if (len < 1)
        {
            return 0;
        }

        while (applicationDataQueue.size() == 0)
        {
            /*
             * We need to read some data.
             */
            if (this.closed)
            {
                if (this.failedWithError)
                {
                    /*
                     * Something went terribly wrong, we should throw an IOException
                     */
                    throw new IOException(TLS_ERROR_MESSAGE);
                }

                /*
                 * Connection has been closed, there is no more data to read.
                 */
                return -1;
            }

            safeReadRecord();
        }

        len = Math.min(len, applicationDataQueue.size());
        applicationDataQueue.removeData(buf, offset, len, 0);
        return len;
    }

    protected void safeReadRecord()
        throws IOException
    {
        try
        {
            if (!recordStream.readRecord())
            {
                // TODO It would be nicer to allow graceful connection close if between records
//                this.failWithError(AlertLevel.warning, AlertDescription.close_notify);
                throw new EOFException();
            }
        }
        catch (TlsFatalAlert e)
        {
            if (!this.closed)
            {
                this.failWithError(AlertLevel.fatal, e.getAlertDescription(), "Failed to read record", e);
            }
            throw e;
        }
        catch (IOException e)
        {
            if (!this.closed)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to read record", e);
            }
            throw e;
        }
        catch (RuntimeException e)
        {
            if (!this.closed)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to read record", e);
            }
            throw e;
        }
    }

    protected void safeWriteRecord(short type, byte[] buf, int offset, int len)
        throws IOException
    {
        try
        {
            recordStream.writeRecord(type, buf, offset, len);
        }
        catch (TlsFatalAlert e)
        {
            if (!this.closed)
            {
                this.failWithError(AlertLevel.fatal, e.getAlertDescription(), "Failed to write record", e);
            }
            throw e;
        }
        catch (IOException e)
        {
            if (!closed)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to write record", e);
            }
            throw e;
        }
        catch (RuntimeException e)
        {
            if (!closed)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to write record", e);
            }
            throw e;
        }
    }

    /**
     * Send some application data to the remote system.
     * <p/>
     * The method will handle fragmentation internally.
     *
     * @param buf    The buffer with the data.
     * @param offset The position in the buffer where the data is placed.
     * @param len    The length of the data.
     * @throws IOException If something goes wrong during sending.
     */
    protected void writeData(byte[] buf, int offset, int len)
        throws IOException
    {
        if (this.closed)
        {
            if (this.failedWithError)
            {
                throw new IOException(TLS_ERROR_MESSAGE);
            }

            throw new IOException("Sorry, connection has been closed, you cannot write more data");
        }

        while (len > 0)
        {
            /*
             * RFC 5246 6.2.1. Zero-length fragments of Application data MAY be sent as they are
             * potentially useful as a traffic analysis countermeasure.
             * 
             * NOTE: Actually, implementations appear to have settled on 1/n-1 record splitting.
             */

            if (this.splitApplicationDataRecords)
            {
                /*
                 * Protect against known IV attack!
                 * 
                 * DO NOT REMOVE THIS CODE, EXCEPT YOU KNOW EXACTLY WHAT YOU ARE DOING HERE.
                 */
                safeWriteRecord(ContentType.application_data, buf, offset, 1);
                ++offset;
                --len;
            }

            if (len > 0)
            {
                // Fragment data according to the current fragment limit.
                int toWrite = Math.min(len, recordStream.getPlaintextLimit());
                safeWriteRecord(ContentType.application_data, buf, offset, toWrite);
                offset += toWrite;
                len -= toWrite;
            }
        }
    }

    protected void writeHandshakeMessage(byte[] buf, int off, int len) throws IOException
    {
        while (len > 0)
        {
            // Fragment data according to the current fragment limit.
            int toWrite = Math.min(len, recordStream.getPlaintextLimit());
            safeWriteRecord(ContentType.handshake, buf, off, toWrite);
            off += toWrite;
            len -= toWrite;
        }
    }

    /**
     * @return An OutputStream which can be used to send data.
     */
    public OutputStream getOutputStream()
    {
        return this.tlsOutputStream;
    }

    /**
     * @return An InputStream which can be used to read data.
     */
    public InputStream getInputStream()
    {
        return this.tlsInputStream;
    }

    /**
     * Terminate this connection with an alert. Can be used for normal closure too.
     * 
     * @param alertLevel
     *            See {@link AlertLevel} for values.
     * @param alertDescription
     *            See {@link AlertDescription} for values.
     * @throws IOException
     *             If alert was fatal.
     */
    protected void failWithError(short alertLevel, short alertDescription, String message, Exception cause)
        throws IOException
    {
        /*
         * Check if the connection is still open.
         */
        if (!closed)
        {
            /*
             * Prepare the message
             */
            this.closed = true;

            if (alertLevel == AlertLevel.fatal)
            {
                /*
                 * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
                 * without proper close_notify messages with level equal to warning.
                 */
                // TODO This isn't quite in the right place. Also, as of TLS 1.1 the above is obsolete.
                invalidateSession();

                this.failedWithError = true;
            }
            raiseAlert(alertLevel, alertDescription, message, cause);
            recordStream.safeClose();
            if (alertLevel != AlertLevel.fatal)
            {
                return;
            }
        }

        throw new IOException(TLS_ERROR_MESSAGE);
    }

    protected void invalidateSession()
    {
        if (this.sessionParameters != null)
        {
            this.sessionParameters.clear();
            this.sessionParameters = null;
        }

        if (this.tlsSession != null)
        {
            this.tlsSession.invalidate();
            this.tlsSession = null;
        }
    }

    protected void processFinishedMessage(ByteArrayInputStream buf)
        throws IOException
    {
        byte[] verify_data = TlsUtils.readFully(expected_verify_data.length, buf);

        assertEmpty(buf);

        /*
         * Compare both checksums.
         */
        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data))
        {
            /*
             * Wrong checksum in the finished message.
             */
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }
    }

    protected void raiseAlert(short alertLevel, short alertDescription, String message, Exception cause)
        throws IOException
    {
        getPeer().notifyAlertRaised(alertLevel, alertDescription, message, cause);

        byte[] error = new byte[2];
        error[0] = (byte)alertLevel;
        error[1] = (byte)alertDescription;

        safeWriteRecord(ContentType.alert, error, 0, 2);
    }

    protected void raiseWarning(short alertDescription, String message)
        throws IOException
    {
        raiseAlert(AlertLevel.warning, alertDescription, message, null);
    }

    protected void sendCertificateMessage(Certificate certificate)
        throws IOException
    {
        if (certificate == null)
        {
            certificate = Certificate.EMPTY_CHAIN;
        }

        if (certificate.getLength() == 0)
        {
            TlsContext context = getContext();
            if (!context.isServer())
            {
                ProtocolVersion serverVersion = getContext().getServerVersion();
                if (serverVersion.isSSL())
                {
                    String message = serverVersion.toString() + " client didn't provide credentials";
                    raiseWarning(AlertDescription.no_certificate, message);
                    return;
                }
            }
        }

        HandshakeMessage message = new HandshakeMessage(HandshakeType.certificate);

        certificate.encode(message);

        message.writeToRecordStream();
    }

    protected void sendChangeCipherSpecMessage()
        throws IOException
    {
        byte[] message = new byte[]{ 1 };
        safeWriteRecord(ContentType.change_cipher_spec, message, 0, message.length);
        recordStream.sentWriteCipherSpec();
    }

    protected void sendFinishedMessage()
        throws IOException
    {
        byte[] verify_data = createVerifyData(getContext().isServer());

        HandshakeMessage message = new HandshakeMessage(HandshakeType.finished, verify_data.length);

        message.write(verify_data);

        message.writeToRecordStream();
    }

    protected void sendSupplementalDataMessage(Vector supplementalData)
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.supplemental_data);

        writeSupplementalData(message, supplementalData);

        message.writeToRecordStream();
    }

    protected byte[] createVerifyData(boolean isServer)
    {
        TlsContext context = getContext();

        if (isServer)
        {
            return TlsUtils.calculateVerifyData(context, ExporterLabel.server_finished,
                getCurrentPRFHash(getContext(), recordStream.getHandshakeHash(), TlsUtils.SSL_SERVER));
        }

        return TlsUtils.calculateVerifyData(context, ExporterLabel.client_finished,
            getCurrentPRFHash(getContext(), recordStream.getHandshakeHash(), TlsUtils.SSL_CLIENT));
    }

    /**
     * Closes this connection.
     *
     * @throws IOException If something goes wrong during closing.
     */
    public void close()
        throws IOException
    {
        handleClose(true);
    }

    protected void handleClose(boolean user_canceled)
        throws IOException
    {
        if (!closed)
        {
            if (user_canceled && !appDataReady)
            {
                raiseWarning(AlertDescription.user_canceled, "User canceled handshake");
            }
            this.failWithError(AlertLevel.warning, AlertDescription.close_notify, "Connection closed", null);
        }
    }

    protected void flush()
        throws IOException
    {
        recordStream.flush();
    }

    protected short processMaxFragmentLengthExtension(Hashtable clientExtensions, Hashtable serverExtensions, short alertDescription)
        throws IOException
    {
        short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
        if (maxFragmentLength >= 0 && !this.resumedSession)
        {
            if (maxFragmentLength != TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions))
            {
                throw new TlsFatalAlert(alertDescription);
            }
        }
        return maxFragmentLength;
    }

    /**
     * Make sure the InputStream 'buf' now empty. Fail otherwise.
     *
     * @param buf The InputStream to check.
     * @throws IOException If 'buf' is not empty.
     */
    protected static void assertEmpty(ByteArrayInputStream buf)
        throws IOException
    {
        if (buf.available() > 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
    }

    protected static byte[] createRandomBlock(boolean useGMTUnixTime, SecureRandom random)
    {
        random.setSeed(Times.nanoTime());

        byte[] result = new byte[32];
        random.nextBytes(result);

        if (useGMTUnixTime)
        {
            TlsUtils.writeGMTUnixTime(result, 0);
        }

        return result;
    }

    protected static byte[] createRenegotiationInfo(byte[] renegotiated_connection)
        throws IOException
    {
        return TlsUtils.encodeOpaque8(renegotiated_connection);
    }

    protected static void establishMasterSecret(TlsContext context, TlsKeyExchange keyExchange)
        throws IOException
    {
        byte[] pre_master_secret = keyExchange.generatePremasterSecret();

        try
        {
            context.getSecurityParameters().masterSecret = TlsUtils.calculateMasterSecret(context, pre_master_secret);
        }
        finally
        {
            // TODO Is there a way to ensure the data is really overwritten?
            /*
             * RFC 2246 8.1. The pre_master_secret should be deleted from memory once the
             * master_secret has been computed.
             */
            if (pre_master_secret != null)
            {
                Arrays.fill(pre_master_secret, (byte)0);
            }
        }
    }

    /**
     * 'sender' only relevant to SSLv3
     */
    protected static byte[] getCurrentPRFHash(TlsContext context, TlsHandshakeHash handshakeHash, byte[] sslSender)
    {
        Digest d = handshakeHash.forkPRFHash();

        if (sslSender != null && TlsUtils.isSSL(context))
        {
            d.update(sslSender, 0, sslSender.length);
        }

        byte[] bs = new byte[d.getDigestSize()];
        d.doFinal(bs, 0);
        return bs;
    }

    protected static Hashtable readExtensions(ByteArrayInputStream input)
        throws IOException
    {
        if (input.available() < 1)
        {
            return null;
        }

        byte[] extBytes = TlsUtils.readOpaque16(input);

        assertEmpty(input);

        ByteArrayInputStream buf = new ByteArrayInputStream(extBytes);

        // Integer -> byte[]
        Hashtable extensions = new Hashtable();

        while (buf.available() > 0)
        {
            Integer extension_type = Integers.valueOf(TlsUtils.readUint16(buf));
            byte[] extension_data = TlsUtils.readOpaque16(buf);

            /*
             * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
             */
            if (null != extensions.put(extension_type, extension_data))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        return extensions;
    }

    protected static Vector readSupplementalDataMessage(ByteArrayInputStream input)
        throws IOException
    {
        byte[] supp_data = TlsUtils.readOpaque24(input);

        assertEmpty(input);

        ByteArrayInputStream buf = new ByteArrayInputStream(supp_data);

        Vector supplementalData = new Vector();

        while (buf.available() > 0)
        {
            int supp_data_type = TlsUtils.readUint16(buf);
            byte[] data = TlsUtils.readOpaque16(buf);

            supplementalData.addElement(new SupplementalDataEntry(supp_data_type, data));
        }

        return supplementalData;
    }

    protected static void writeExtensions(OutputStream output, Hashtable extensions)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        Enumeration keys = extensions.keys();
        while (keys.hasMoreElements())
        {
            Integer key = (Integer)keys.nextElement();
            int extension_type = key.intValue();
            byte[] extension_data = (byte[])extensions.get(key);

            TlsUtils.checkUint16(extension_type);
            TlsUtils.writeUint16(extension_type, buf);
            TlsUtils.writeOpaque16(extension_data, buf);
        }

        byte[] extBytes = buf.toByteArray();

        TlsUtils.writeOpaque16(extBytes, output);
    }

    protected static void writeSupplementalData(OutputStream output, Vector supplementalData)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        for (int i = 0; i < supplementalData.size(); ++i)
        {
            SupplementalDataEntry entry = (SupplementalDataEntry)supplementalData.elementAt(i);

            int supp_data_type = entry.getDataType();
            TlsUtils.checkUint16(supp_data_type);
            TlsUtils.writeUint16(supp_data_type, buf);
            TlsUtils.writeOpaque16(entry.getData(), buf);
        }

        byte[] supp_data = buf.toByteArray();

        TlsUtils.writeOpaque24(supp_data, output);
    }

    protected static int getPRFAlgorithm(TlsContext context, int ciphersuite) throws IOException
    {
        boolean isTLSv12 = TlsUtils.isTLSv12(context);

        switch (ciphersuite)
        {
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
        {
            if (isTLSv12)
            {
                return PRFAlgorithm.tls_prf_sha256;
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        {
            if (isTLSv12)
            {
                return PRFAlgorithm.tls_prf_sha384;
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
        {
            if (isTLSv12)
            {
                return PRFAlgorithm.tls_prf_sha384;
            }
            return PRFAlgorithm.tls_prf_legacy;
        }

        default:
        {
            if (isTLSv12)
            {
                return PRFAlgorithm.tls_prf_sha256;
            }
            return PRFAlgorithm.tls_prf_legacy;
        }
        }
    }

    class HandshakeMessage extends ByteArrayOutputStream
    {
        HandshakeMessage(short handshakeType) throws IOException
        {
            this(handshakeType, 60);
        }

        HandshakeMessage(short handshakeType, int length) throws IOException
        {
            super(length + 4);
            TlsUtils.writeUint8(handshakeType, this);
            // Reserve space for length
            count += 3;
        }

        void writeToRecordStream() throws IOException
        {
            // Patch actual length back in
            int length = count - 4;
            TlsUtils.checkUint24(length);
            TlsUtils.writeUint24(length, buf, 1);
            writeHandshakeMessage(buf, 0, count);
            buf = null;
        }
    }
}
