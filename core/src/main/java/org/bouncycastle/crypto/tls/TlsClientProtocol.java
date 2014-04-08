package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;
import org.bouncycastle.util.Arrays;

public class TlsClientProtocol
    extends TlsProtocol
{
    protected TlsClient tlsClient = null;
    protected TlsClientContextImpl tlsClientContext = null;

    protected byte[] selectedSessionID = null;

    protected TlsKeyExchange keyExchange = null;
    protected TlsAuthentication authentication = null;

    protected CertificateStatus certificateStatus = null;
    protected CertificateRequest certificateRequest = null;

    private static SecureRandom createSecureRandom()
    {
        /*
         * We use our threaded seed generator to generate a good random seed. If the user has a
         * better random seed, he should use the constructor with a SecureRandom.
         */
        ThreadedSeedGenerator tsg = new ThreadedSeedGenerator();
        SecureRandom random = new SecureRandom();

        /*
         * Hopefully, 20 bytes in fast mode are good enough.
         */
        random.setSeed(tsg.generateSeed(20, true));

        return random;
    }

    public TlsClientProtocol(InputStream input, OutputStream output)
    {
        this(input, output, createSecureRandom());
    }

    public TlsClientProtocol(InputStream input, OutputStream output, SecureRandom secureRandom)
    {
        super(input, output, secureRandom);
    }

    /**
     * Initiates a TLS handshake in the role of client
     *
     * @param tlsClient The {@link TlsClient} to use for the handshake.
     * @throws IOException If handshake was not successful.
     */
    public void connect(TlsClient tlsClient) throws IOException
    {
        if (tlsClient == null)
        {
            throw new IllegalArgumentException("'tlsClient' cannot be null");
        }
        if (this.tlsClient != null)
        {
            throw new IllegalStateException("'connect' can only be called once");
        }

        this.tlsClient = tlsClient;

        this.securityParameters = new SecurityParameters();
        this.securityParameters.entity = ConnectionEnd.client;
        this.securityParameters.clientRandom = createRandomBlock(tlsClient.shouldUseGMTUnixTime(), secureRandom);

        this.tlsClientContext = new TlsClientContextImpl(secureRandom, securityParameters);
        this.tlsClient.init(tlsClientContext);
        this.recordStream.init(tlsClientContext);

        TlsSession sessionToResume = tlsClient.getSessionToResume();
        if (sessionToResume != null)
        {
            SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
            if (sessionParameters != null)
            {
                this.tlsSession = sessionToResume;
                this.sessionParameters = sessionParameters;
            }
        }

        sendClientHelloMessage();
        this.connection_state = CS_CLIENT_HELLO;

        completeHandshake();
    }

    protected void cleanupHandshake()
    {
        super.cleanupHandshake();

        this.selectedSessionID = null;
        this.keyExchange = null;
        this.authentication = null;
        this.certificateStatus = null;
        this.certificateRequest = null;
    }

    protected AbstractTlsContext getContext()
    {
        return tlsClientContext;
    }

    protected TlsPeer getPeer()
    {
        return tlsClient;
    }

    protected void handleHandshakeMessage(short type, byte[] data)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(data);

        if (this.resumedSession)
        {
            if (type != HandshakeType.finished || this.connection_state != CS_SERVER_HELLO)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            processFinishedMessage(buf);
            this.connection_state = CS_SERVER_FINISHED;

            sendFinishedMessage();
            this.connection_state = CS_CLIENT_FINISHED;
            this.connection_state = CS_END;

            return;
        }

        switch (type)
        {
        case HandshakeType.certificate:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_SERVER_SUPPLEMENTAL_DATA:
            {
                // Parse the Certificate message and send to cipher suite

                this.peerCertificate = Certificate.parse(buf);

                assertEmpty(buf);

                // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
                if (this.peerCertificate == null || this.peerCertificate.isEmpty())
                {
                    this.allowCertificateStatus = false;
                }

                this.keyExchange.processServerCertificate(this.peerCertificate);

                this.authentication = tlsClient.getAuthentication();
                this.authentication.notifyServerCertificate(this.peerCertificate);

                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_CERTIFICATE;
            break;
        }
        case HandshakeType.certificate_status:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_CERTIFICATE:
            {
                if (!this.allowCertificateStatus)
                {
                    /*
                     * RFC 3546 3.6. If a server returns a "CertificateStatus" message, then the
                     * server MUST have included an extension of type "status_request" with empty
                     * "extension_data" in the extended server hello..
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                this.certificateStatus = CertificateStatus.parse(buf);

                assertEmpty(buf);

                // TODO[RFC 3546] Figure out how to provide this to the client/authentication.

                this.connection_state = CS_CERTIFICATE_STATUS;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.finished:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_FINISHED:
            {
                if (this.expectSessionTicket)
                {
                    /*
                     * RFC 5077 3.3. This message MUST be sent if the server included a
                     * SessionTicket extension in the ServerHello.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                // NB: Fall through to next case label
            }
            case CS_SERVER_SESSION_TICKET:
            {
                processFinishedMessage(buf);
                this.connection_state = CS_SERVER_FINISHED;
                this.connection_state = CS_END;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.server_hello:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_HELLO:
            {
                receiveServerHelloMessage(buf);
                this.connection_state = CS_SERVER_HELLO;

                if (this.securityParameters.maxFragmentLength >= 0)
                {
                    int plainTextLimit = 1 << (8 + this.securityParameters.maxFragmentLength);
                    recordStream.setPlaintextLimit(plainTextLimit);
                }

                this.securityParameters.prfAlgorithm = getPRFAlgorithm(getContext(),
                    this.securityParameters.getCipherSuite());

                /*
                 * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify
                 * verify_data_length has a verify_data_length equal to 12. This includes all
                 * existing cipher suites.
                 */
                this.securityParameters.verifyDataLength = 12;

                this.recordStream.notifyHelloComplete();

                if (this.resumedSession)
                {
                    this.securityParameters.masterSecret = Arrays.clone(this.sessionParameters.getMasterSecret());
                    this.recordStream.setPendingConnectionState(getPeer().getCompression(), getPeer().getCipher());

                    sendChangeCipherSpecMessage();
                }
                else
                {
                    invalidateSession();

                    if (this.selectedSessionID.length > 0)
                    {
                        this.tlsSession = new TlsSessionImpl(this.selectedSessionID, null);
                    }
                }

                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.supplemental_data:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(readSupplementalDataMessage(buf));
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.server_hello_done:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_SERVER_SUPPLEMENTAL_DATA:
            {
                // There was no server certificate message; check it's OK
                this.keyExchange.skipServerCredentials();
                this.authentication = null;

                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE:
            case CS_CERTIFICATE_STATUS:
            {
                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label
            }
            case CS_SERVER_KEY_EXCHANGE:
            case CS_CERTIFICATE_REQUEST:
            {
                assertEmpty(buf);

                this.connection_state = CS_SERVER_HELLO_DONE;

                this.recordStream.getHandshakeHash().sealHashAlgorithms();

                Vector clientSupplementalData = tlsClient.getClientSupplementalData();
                if (clientSupplementalData != null)
                {
                    sendSupplementalDataMessage(clientSupplementalData);
                }
                this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;

                TlsCredentials clientCreds = null;
                if (certificateRequest == null)
                {
                    this.keyExchange.skipClientCredentials();
                }
                else
                {
                    clientCreds = this.authentication.getClientCredentials(certificateRequest);

                    if (clientCreds == null)
                    {
                        this.keyExchange.skipClientCredentials();

                        /*
                         * RFC 5246 If no suitable certificate is available, the client MUST send a
                         * certificate message containing no certificates.
                         * 
                         * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                         */
                        sendCertificateMessage(Certificate.EMPTY_CHAIN);
                    }
                    else
                    {
                        this.keyExchange.processClientCredentials(clientCreds);

                        sendCertificateMessage(clientCreds.getCertificate());
                    }
                }

                this.connection_state = CS_CLIENT_CERTIFICATE;

                /*
                 * Send the client key exchange message, depending on the key exchange we are using
                 * in our CipherSuite.
                 */
                sendClientKeyExchangeMessage();
                this.connection_state = CS_CLIENT_KEY_EXCHANGE;

                establishMasterSecret(getContext(), keyExchange);
                recordStream.setPendingConnectionState(getPeer().getCompression(), getPeer().getCipher());

                TlsHandshakeHash prepareFinishHash = recordStream.prepareToFinish();

                if (clientCreds != null && clientCreds instanceof TlsSignerCredentials)
                {
                    TlsSignerCredentials signerCredentials = (TlsSignerCredentials)clientCreds;

                    /*
                     * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
                     */
                    SignatureAndHashAlgorithm signatureAndHashAlgorithm;
                    byte[] hash;

                    if (TlsUtils.isTLSv12(getContext()))
                    {
                        signatureAndHashAlgorithm = signerCredentials.getSignatureAndHashAlgorithm();
                        if (signatureAndHashAlgorithm == null)
                        {
                            throw new TlsFatalAlert(AlertDescription.internal_error);
                        }

                        hash = prepareFinishHash.getFinalHash(signatureAndHashAlgorithm.getHash());
                    }
                    else
                    {
                        signatureAndHashAlgorithm = null;
                        hash = getCurrentPRFHash(getContext(), prepareFinishHash, null);
                    }

                    byte[] signature = signerCredentials.generateCertificateSignature(hash);
                    DigitallySigned certificateVerify = new DigitallySigned(signatureAndHashAlgorithm, signature);
                    sendCertificateVerifyMessage(certificateVerify);

                    this.connection_state = CS_CERTIFICATE_VERIFY;
                }

                sendChangeCipherSpecMessage();
                sendFinishedMessage();
                this.connection_state = CS_CLIENT_FINISHED;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            break;
        }
        case HandshakeType.server_key_exchange:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_SERVER_SUPPLEMENTAL_DATA:
            {
                // There was no server certificate message; check it's OK
                this.keyExchange.skipServerCredentials();
                this.authentication = null;

                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE:
            case CS_CERTIFICATE_STATUS:
            {
                this.keyExchange.processServerKeyExchange(buf);

                assertEmpty(buf);
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_KEY_EXCHANGE;
            break;
        }
        case HandshakeType.certificate_request:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_CERTIFICATE:
            case CS_CERTIFICATE_STATUS:
            {
                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label
            }
            case CS_SERVER_KEY_EXCHANGE:
            {
                if (this.authentication == null)
                {
                    /*
                     * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server
                     * to request client identification.
                     */
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }

                this.certificateRequest = CertificateRequest.parse(getContext(), buf);

                assertEmpty(buf);

                this.keyExchange.validateCertificateRequest(this.certificateRequest);

                /*
                 * TODO Give the client a chance to immediately select the CertificateVerify hash
                 * algorithm here to avoid tracking the other hash algorithms unnecessarily?
                 */
                TlsUtils.trackHashAlgorithms(this.recordStream.getHandshakeHash(),
                    this.certificateRequest.getSupportedSignatureAlgorithms());

                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_CERTIFICATE_REQUEST;
            break;
        }
        case HandshakeType.session_ticket:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_FINISHED:
            {
                if (!this.expectSessionTicket)
                {
                    /*
                     * RFC 5077 3.3. This message MUST NOT be sent if the server did not include a
                     * SessionTicket extension in the ServerHello.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                /*
                 * RFC 5077 3.4. If the client receives a session ticket from the server, then it
                 * discards any Session ID that was sent in the ServerHello.
                 */
                invalidateSession();

                receiveNewSessionTicketMessage(buf);
                this.connection_state = CS_SERVER_SESSION_TICKET;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }
        case HandshakeType.hello_request:
        {
            assertEmpty(buf);

            /*
             * RFC 2246 7.4.1.1 Hello request This message will be ignored by the client if the
             * client is currently negotiating a session. This message may be ignored by the client
             * if it does not wish to renegotiate a session, or the client may, if it wishes,
             * respond with a no_renegotiation alert.
             */
            if (this.connection_state == CS_END)
            {
                /*
                 * RFC 5746 4.5 SSLv3 clients that refuse renegotiation SHOULD use a fatal
                 * handshake_failure alert.
                 */
                if (TlsUtils.isSSL(getContext()))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }

                String message = "Renegotiation not supported";
                raiseWarning(AlertDescription.no_renegotiation, message);
            }
            break;
        }
        case HandshakeType.client_hello:
        case HandshakeType.client_key_exchange:
        case HandshakeType.certificate_verify:
        case HandshakeType.hello_verify_request:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleSupplementalData(Vector serverSupplementalData)
        throws IOException
    {
        this.tlsClient.processServerSupplementalData(serverSupplementalData);
        this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

        this.keyExchange = tlsClient.getKeyExchange();
        this.keyExchange.init(getContext());
    }

    protected void receiveNewSessionTicketMessage(ByteArrayInputStream buf)
        throws IOException
    {
        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);

        TlsProtocol.assertEmpty(buf);

        tlsClient.notifyNewSessionTicket(newSessionTicket);
    }

    protected void receiveServerHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {
        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        if (server_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        // Check that this matches what the server is sending in the record layer
        if (!server_version.equals(this.recordStream.getReadVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        ProtocolVersion client_version = getContext().getClientVersion();
        if (!server_version.isEqualOrEarlierVersionOf(client_version))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        this.recordStream.setWriteVersion(server_version);
        getContext().setServerVersion(server_version);
        this.tlsClient.notifyServerVersion(server_version);

        /*
         * Read the server random
         */
        this.securityParameters.serverRandom = TlsUtils.readFully(32, buf);

        this.selectedSessionID = TlsUtils.readOpaque8(buf);
        if (this.selectedSessionID.length > 32)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        this.tlsClient.notifySessionID(this.selectedSessionID);

        this.resumedSession = this.selectedSessionID.length > 0 && this.tlsSession != null
            && Arrays.areEqual(this.selectedSessionID, this.tlsSession.getSessionID());

        /*
         * Find out which CipherSuite the server has chosen and check that it was one of the offered
         * ones, and is a valid selection for the negotiated version.
         */
        int selectedCipherSuite = TlsUtils.readUint16(buf);
        if (!Arrays.contains(this.offeredCipherSuites, selectedCipherSuite)
            || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
            || selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            || !TlsUtils.isValidCipherSuiteForVersion(selectedCipherSuite, server_version))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        this.tlsClient.notifySelectedCipherSuite(selectedCipherSuite);

        /*
         * Find out which CompressionMethod the server has chosen and check that it was one of the
         * offered ones.
         */
        short selectedCompressionMethod = TlsUtils.readUint8(buf);
        if (!Arrays.contains(this.offeredCompressionMethods, selectedCompressionMethod))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        this.tlsClient.notifySelectedCompressionMethod(selectedCompressionMethod);

        /*
         * RFC3546 2.2 The extended server hello message format MAY be sent in place of the server
         * hello message when the client has requested extended functionality via the extended
         * client hello message specified in Section 2.1. ... Note that the extended server hello
         * message is only sent in response to an extended client hello message. This prevents the
         * possibility that the extended server hello message could "break" existing TLS 1.0
         * clients.
         */
        this.serverExtensions = readExtensions(buf);

        /*
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message.
         * 
         * However, see RFC 5746 exception below. We always include the SCSV, so an Extended Server
         * Hello is always allowed.
         */
        if (this.serverExtensions != null)
        {
            Enumeration e = this.serverExtensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();

                /*
                 * RFC 5746 3.6. Note that sending a "renegotiation_info" extension in response to a
                 * ClientHello containing only the SCSV is an explicit exception to the prohibition
                 * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                 * only allowed because the client is signaling its willingness to receive the
                 * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                 */
                if (extType.equals(EXT_RenegotiationInfo))
                {
                    continue;
                }

                /*
                 * RFC 3546 2.3. If [...] the older session is resumed, then the server MUST ignore
                 * extensions appearing in the client hello, and send a server hello containing no
                 * extensions[.]
                 */
                if (this.resumedSession)
                {
                    // TODO[compat-gnutls] GnuTLS test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-openssl] OpenSSL test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-polarssl] PolarSSL test server sends server extensions e.g. ec_point_formats
//                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                /*
                 * RFC 5246 7.4.1.4 An extension type MUST NOT appear in the ServerHello unless the
                 * same extension type appeared in the corresponding ClientHello. If a client
                 * receives an extension type in ServerHello that it did not request in the
                 * associated ClientHello, it MUST abort the handshake with an unsupported_extension
                 * fatal alert.
                 */
                if (null == TlsUtils.getExtensionData(this.clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                }
            }
        }

        /*
         * RFC 5746 3.4. Client Behavior: Initial Handshake
         */
        {
            /*
             * When a ServerHello is received, the client MUST check if it includes the
             * "renegotiation_info" extension:
             */
            byte[] renegExtData = TlsUtils.getExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
            if (renegExtData != null)
            {
                /*
                 * If the extension is present, set the secure_renegotiation flag to TRUE. The
                 * client MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                 * handshake_failure alert).
                 */
                this.secure_renegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        // TODO[compat-gnutls] GnuTLS test server fails to send renegotiation_info extension when resuming
        this.tlsClient.notifySecureRenegotiation(this.secure_renegotiation);

        Hashtable sessionClientExtensions = clientExtensions, sessionServerExtensions = serverExtensions;
        if (this.resumedSession)
        {
            if (selectedCipherSuite != this.sessionParameters.getCipherSuite()
                || selectedCompressionMethod != this.sessionParameters.getCompressionAlgorithm())
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            sessionClientExtensions = null;
            sessionServerExtensions = this.sessionParameters.readServerExtensions();
        }

        this.securityParameters.cipherSuite = selectedCipherSuite;
        this.securityParameters.compressionAlgorithm = selectedCompressionMethod;

        if (sessionServerExtensions != null)
        {
            this.securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(sessionServerExtensions);

            this.securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(sessionClientExtensions,
                sessionServerExtensions, AlertDescription.illegal_parameter);

            this.securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(sessionServerExtensions);

            /*
             * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
             * a session resumption handshake.
             */
            this.allowCertificateStatus = !this.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions,
                    TlsExtensionsUtils.EXT_status_request, AlertDescription.illegal_parameter);

            this.expectSessionTicket = !this.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.illegal_parameter);
        }

        if (sessionClientExtensions != null)
        {
            this.tlsClient.processServerExtensions(sessionServerExtensions);
        }
    }

    protected void sendCertificateVerifyMessage(DigitallySigned certificateVerify)
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.certificate_verify);

        certificateVerify.encode(message);

        message.writeToRecordStream();
    }

    protected void sendClientHelloMessage()
        throws IOException
    {
        this.recordStream.setWriteVersion(this.tlsClient.getClientHelloRecordLayerVersion());

        ProtocolVersion client_version = this.tlsClient.getClientVersion();
        if (client_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        getContext().setClientVersion(client_version);

        /*
         * TODO RFC 5077 3.4. When presenting a ticket, the client MAY generate and include a
         * Session ID in the TLS ClientHello.
         */
        byte[] session_id = TlsUtils.EMPTY_BYTES;
        if (this.tlsSession != null)
        {
            session_id = this.tlsSession.getSessionID();
            if (session_id == null || session_id.length > 32)
            {
                session_id = TlsUtils.EMPTY_BYTES;
            }
        }

        this.offeredCipherSuites = this.tlsClient.getCipherSuites();

        this.offeredCompressionMethods = this.tlsClient.getCompressionMethods();

        if (session_id.length > 0 && this.sessionParameters != null)
        {
            if (!Arrays.contains(this.offeredCipherSuites, sessionParameters.getCipherSuite())
                || !Arrays.contains(this.offeredCompressionMethods, sessionParameters.getCompressionAlgorithm()))
            {
                session_id = TlsUtils.EMPTY_BYTES;
            }
        }

        this.clientExtensions = this.tlsClient.getClientExtensions();

        HandshakeMessage message = new HandshakeMessage(HandshakeType.client_hello);

        TlsUtils.writeVersion(client_version, message);

        message.write(this.securityParameters.getClientRandom());

        TlsUtils.writeOpaque8(session_id, message);

        // Cipher Suites (and SCSV)
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */
            byte[] renegExtData = TlsUtils.getExtensionData(clientExtensions, EXT_RenegotiationInfo);
            boolean noRenegExt = (null == renegExtData);

            boolean noSCSV = !Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

            if (noRenegExt && noSCSV)
            {
                // TODO Consider whether to default to a client extension instead
//                this.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(this.clientExtensions);
//                this.clientExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
                this.offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            }

            TlsUtils.writeUint16ArrayWithUint16Length(offeredCipherSuites, message);
        }

        TlsUtils.writeUint8ArrayWithUint8Length(offeredCompressionMethods, message);

        if (clientExtensions != null)
        {
            writeExtensions(message, clientExtensions);
        }

        message.writeToRecordStream();
    }

    protected void sendClientKeyExchangeMessage()
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.client_key_exchange);

        this.keyExchange.generateClientKeyExchange(message);

        message.writeToRecordStream();
    }
}
