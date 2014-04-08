package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Arrays;

public class DTLSClientProtocol
    extends DTLSProtocol
{
    public DTLSClientProtocol(SecureRandom secureRandom)
    {
        super(secureRandom);
    }

    public DTLSTransport connect(TlsClient client, DatagramTransport transport)
        throws IOException
    {
        if (client == null)
        {
            throw new IllegalArgumentException("'client' cannot be null");
        }
        if (transport == null)
        {
            throw new IllegalArgumentException("'transport' cannot be null");
        }

        SecurityParameters securityParameters = new SecurityParameters();
        securityParameters.entity = ConnectionEnd.client;
        securityParameters.clientRandom = TlsProtocol.createRandomBlock(client.shouldUseGMTUnixTime(), secureRandom);

        ClientHandshakeState state = new ClientHandshakeState();
        state.client = client;
        state.clientContext = new TlsClientContextImpl(secureRandom, securityParameters);
        client.init(state.clientContext);

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, state.clientContext, client, ContentType.handshake);

        TlsSession sessionToResume = state.client.getSessionToResume();
        if (sessionToResume != null)
        {
            SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
            if (sessionParameters != null)
            {
                state.tlsSession = sessionToResume;
                state.sessionParameters = sessionParameters;
            }
        }

        try
        {
            return clientHandshake(state, recordLayer);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            recordLayer.fail(fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (IOException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected DTLSTransport clientHandshake(ClientHandshakeState state, DTLSRecordLayer recordLayer)
        throws IOException
    {
        SecurityParameters securityParameters = state.clientContext.getSecurityParameters();
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.clientContext, recordLayer);

        byte[] clientHelloBody = generateClientHello(state, state.client);
        handshake.sendMessage(HandshakeType.client_hello, clientHelloBody);

        DTLSReliableHandshake.Message serverMessage = handshake.receiveMessage();

        while (serverMessage.getType() == HandshakeType.hello_verify_request)
        {
            ProtocolVersion recordLayerVersion = recordLayer.resetDiscoveredPeerVersion();
            ProtocolVersion client_version = state.clientContext.getClientVersion();

            /*
             * RFC 6347 4.2.1 DTLS 1.2 server implementations SHOULD use DTLS version 1.0 regardless of
             * the version of TLS that is expected to be negotiated. DTLS 1.2 and 1.0 clients MUST use
             * the version solely to indicate packet formatting (which is the same in both DTLS 1.2 and
             * 1.0) and not as part of version negotiation.
             */
            if (!recordLayerVersion.isEqualOrEarlierVersionOf(client_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            byte[] cookie = processHelloVerifyRequest(state, serverMessage.getBody());
            byte[] patched = patchClientHelloWithCookie(clientHelloBody, cookie);

            handshake.resetHandshakeMessagesDigest();
            handshake.sendMessage(HandshakeType.client_hello, patched);

            serverMessage = handshake.receiveMessage();
        }

        if (serverMessage.getType() == HandshakeType.server_hello)
        {
            reportServerVersion(state, recordLayer.getDiscoveredPeerVersion());

            processServerHello(state, serverMessage.getBody());
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        if (state.maxFragmentLength >= 0)
        {
            int plainTextLimit = 1 << (8 + state.maxFragmentLength);
            recordLayer.setPlaintextLimit(plainTextLimit);
        }

        securityParameters.cipherSuite = state.selectedCipherSuite;
        securityParameters.compressionAlgorithm = state.selectedCompressionMethod;
        securityParameters.prfAlgorithm = TlsProtocol.getPRFAlgorithm(state.clientContext, state.selectedCipherSuite);

        /*
         * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify verify_data_length has
         * a verify_data_length equal to 12. This includes all existing cipher suites.
         */
        securityParameters.verifyDataLength = 12;

        handshake.notifyHelloComplete();

        boolean resumedSession = state.selectedSessionID.length > 0 && state.tlsSession != null
            && Arrays.areEqual(state.selectedSessionID, state.tlsSession.getSessionID());

        if (resumedSession)
        {
            if (securityParameters.getCipherSuite() != state.sessionParameters.getCipherSuite()
                || securityParameters.getCompressionAlgorithm() != state.sessionParameters.getCompressionAlgorithm())
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            securityParameters.masterSecret = Arrays.clone(state.sessionParameters.getMasterSecret());
            recordLayer.initPendingEpoch(state.client.getCipher());

            // NOTE: Calculated exclusive of the actual Finished message from the server
            byte[] expectedServerVerifyData = TlsUtils.calculateVerifyData(state.clientContext, ExporterLabel.server_finished,
                TlsProtocol.getCurrentPRFHash(state.clientContext, handshake.getHandshakeHash(), null));
            processFinished(handshake.receiveMessageBody(HandshakeType.finished), expectedServerVerifyData);

            // NOTE: Calculated exclusive of the Finished message itself
            byte[] clientVerifyData = TlsUtils.calculateVerifyData(state.clientContext, ExporterLabel.client_finished,
                TlsProtocol.getCurrentPRFHash(state.clientContext, handshake.getHandshakeHash(), null));
            handshake.sendMessage(HandshakeType.finished, clientVerifyData);

            handshake.finish();

            state.clientContext.setResumableSession(state.tlsSession);

            state.client.notifyHandshakeComplete();

            return new DTLSTransport(recordLayer);
        }

        invalidateSession(state);

        if (state.selectedSessionID.length > 0)
        {
            state.tlsSession = new TlsSessionImpl(state.selectedSessionID, null);
        }

        serverMessage = handshake.receiveMessage();

        if (serverMessage.getType() == HandshakeType.supplemental_data)
        {
            processServerSupplementalData(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            state.client.processServerSupplementalData(null);
        }

        state.keyExchange = state.client.getKeyExchange();
        state.keyExchange.init(state.clientContext);

        Certificate serverCertificate = null;

        if (serverMessage.getType() == HandshakeType.certificate)
        {
            serverCertificate = processServerCertificate(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, Certificate is optional
            state.keyExchange.skipServerCredentials();
        }

        // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
        if (serverCertificate == null || serverCertificate.isEmpty())
        {
            state.allowCertificateStatus = false;
        }

        if (serverMessage.getType() == HandshakeType.certificate_status)
        {
            processCertificateStatus(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, CertificateStatus is optional
        }

        if (serverMessage.getType() == HandshakeType.server_key_exchange)
        {
            processServerKeyExchange(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, ServerKeyExchange is optional
            state.keyExchange.skipServerKeyExchange();
        }

        if (serverMessage.getType() == HandshakeType.certificate_request)
        {
            processCertificateRequest(state, serverMessage.getBody());

            /*
             * TODO Give the client a chance to immediately select the CertificateVerify hash
             * algorithm here to avoid tracking the other hash algorithms unnecessarily?
             */
            TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(),
                state.certificateRequest.getSupportedSignatureAlgorithms());

            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, CertificateRequest is optional
        }

        if (serverMessage.getType() == HandshakeType.server_hello_done)
        {
            if (serverMessage.getBody().length != 0)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        handshake.getHandshakeHash().sealHashAlgorithms();

        Vector clientSupplementalData = state.client.getClientSupplementalData();
        if (clientSupplementalData != null)
        {
            byte[] supplementalDataBody = generateSupplementalData(clientSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        if (state.certificateRequest != null)
        {
            state.clientCredentials = state.authentication.getClientCredentials(state.certificateRequest);

            /*
             * RFC 5246 If no suitable certificate is available, the client MUST send a certificate
             * message containing no certificates.
             * 
             * NOTE: In previous RFCs, this was SHOULD instead of MUST.
             */
            Certificate clientCertificate = null;
            if (state.clientCredentials != null)
            {
                clientCertificate = state.clientCredentials.getCertificate();
            }
            if (clientCertificate == null)
            {
                clientCertificate = Certificate.EMPTY_CHAIN;
            }

            byte[] certificateBody = generateCertificate(clientCertificate);
            handshake.sendMessage(HandshakeType.certificate, certificateBody);
        }

        if (state.clientCredentials != null)
        {
            state.keyExchange.processClientCredentials(state.clientCredentials);
        }
        else
        {
            state.keyExchange.skipClientCredentials();
        }

        byte[] clientKeyExchangeBody = generateClientKeyExchange(state);
        handshake.sendMessage(HandshakeType.client_key_exchange, clientKeyExchangeBody);

        TlsProtocol.establishMasterSecret(state.clientContext, state.keyExchange);
        recordLayer.initPendingEpoch(state.client.getCipher());

        TlsHandshakeHash prepareFinishHash = handshake.prepareToFinish();

        if (state.clientCredentials != null && state.clientCredentials instanceof TlsSignerCredentials)
        {
            TlsSignerCredentials signerCredentials = (TlsSignerCredentials)state.clientCredentials;

            /*
             * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
             */
            SignatureAndHashAlgorithm signatureAndHashAlgorithm;
            byte[] hash;

            if (TlsUtils.isTLSv12(state.clientContext))
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
                hash = TlsProtocol.getCurrentPRFHash(state.clientContext, prepareFinishHash, null);
            }

            byte[] signature = signerCredentials.generateCertificateSignature(hash);
            DigitallySigned certificateVerify = new DigitallySigned(signatureAndHashAlgorithm, signature);
            byte[] certificateVerifyBody = generateCertificateVerify(state, certificateVerify);
            handshake.sendMessage(HandshakeType.certificate_verify, certificateVerifyBody);
        }

        // NOTE: Calculated exclusive of the Finished message itself
        byte[] clientVerifyData = TlsUtils.calculateVerifyData(state.clientContext, ExporterLabel.client_finished,
            TlsProtocol.getCurrentPRFHash(state.clientContext, handshake.getHandshakeHash(), null));
        handshake.sendMessage(HandshakeType.finished, clientVerifyData);

        if (state.expectSessionTicket)
        {
            serverMessage = handshake.receiveMessage();
            if (serverMessage.getType() == HandshakeType.session_ticket)
            {
                processNewSessionTicket(state, serverMessage.getBody());
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        // NOTE: Calculated exclusive of the actual Finished message from the server
        byte[] expectedServerVerifyData = TlsUtils.calculateVerifyData(state.clientContext, ExporterLabel.server_finished,
            TlsProtocol.getCurrentPRFHash(state.clientContext, handshake.getHandshakeHash(), null));
        processFinished(handshake.receiveMessageBody(HandshakeType.finished), expectedServerVerifyData);

        handshake.finish();

        if (state.tlsSession != null)
        {
            state.sessionParameters = new SessionParameters.Builder()
                .setCipherSuite(securityParameters.cipherSuite)
                .setCompressionAlgorithm(securityParameters.compressionAlgorithm)
                .setMasterSecret(securityParameters.masterSecret)
                .setPeerCertificate(serverCertificate)
                .build();

            state.tlsSession = TlsUtils.importSession(state.tlsSession.getSessionID(), state.sessionParameters);

            state.clientContext.setResumableSession(state.tlsSession);
        }

        state.client.notifyHandshakeComplete();

        return new DTLSTransport(recordLayer);
    }

    protected byte[] generateCertificateVerify(ClientHandshakeState state, DigitallySigned certificateVerify)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateVerify.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateClientHello(ClientHandshakeState state, TlsClient client)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        ProtocolVersion client_version = client.getClientVersion();
        if (!client_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        state.clientContext.setClientVersion(client_version);
        TlsUtils.writeVersion(client_version, buf);

        buf.write(state.clientContext.getSecurityParameters().getClientRandom());

        // Session ID
        byte[] session_id = TlsUtils.EMPTY_BYTES;
        if (state.tlsSession != null)
        {
            session_id = state.tlsSession.getSessionID();
            if (session_id == null || session_id.length > 32)
            {
                session_id = TlsUtils.EMPTY_BYTES;
            }
        }
        TlsUtils.writeOpaque8(session_id, buf);

        // Cookie
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, buf);

        /*
         * Cipher suites
         */
        state.offeredCipherSuites = client.getCipherSuites();

        // Integer -> byte[]
        state.clientExtensions = client.getClientExtensions();

        // Cipher Suites (and SCSV)
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */
            byte[] renegExtData = TlsUtils.getExtensionData(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
            boolean noRenegExt = (null == renegExtData);

            boolean noSCSV = !Arrays.contains(state.offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

            if (noRenegExt && noSCSV)
            {
                // TODO Consider whether to default to a client extension instead
                state.offeredCipherSuites = Arrays.append(state.offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            }

            TlsUtils.writeUint16ArrayWithUint16Length(state.offeredCipherSuites, buf);
        }

        // TODO Add support for compression
        // Compression methods
        // state.offeredCompressionMethods = client.getCompressionMethods();
        state.offeredCompressionMethods = new short[]{ CompressionMethod._null };

        TlsUtils.writeUint8ArrayWithUint8Length(state.offeredCompressionMethods, buf);

        // Extensions
        if (state.clientExtensions != null)
        {
            TlsProtocol.writeExtensions(buf, state.clientExtensions);
        }

        return buf.toByteArray();
    }

    protected byte[] generateClientKeyExchange(ClientHandshakeState state)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        state.keyExchange.generateClientKeyExchange(buf);
        return buf.toByteArray();
    }

    protected void invalidateSession(ClientHandshakeState state)
    {
        if (state.sessionParameters != null)
        {
            state.sessionParameters.clear();
            state.sessionParameters = null;
        }

        if (state.tlsSession != null)
        {
            state.tlsSession.invalidate();
            state.tlsSession = null;
        }
    }

    protected void processCertificateRequest(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        if (state.authentication == null)
        {
            /*
             * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server to
             * request client identification.
             */
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        state.certificateRequest = CertificateRequest.parse(state.clientContext, buf);

        TlsProtocol.assertEmpty(buf);

        state.keyExchange.validateCertificateRequest(state.certificateRequest);
    }

    protected void processCertificateStatus(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        if (!state.allowCertificateStatus)
        {
            /*
             * RFC 3546 3.6. If a server returns a "CertificateStatus" message, then the
             * server MUST have included an extension of type "status_request" with empty
             * "extension_data" in the extended server hello..
             */
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        state.certificateStatus = CertificateStatus.parse(buf);

        TlsProtocol.assertEmpty(buf);

        // TODO[RFC 3546] Figure out how to provide this to the client/authentication.
    }

    protected byte[] processHelloVerifyRequest(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        byte[] cookie = TlsUtils.readOpaque8(buf);

        TlsProtocol.assertEmpty(buf);

        // TODO Seems this behaviour is not yet in line with OpenSSL for DTLS 1.2
//        reportServerVersion(state, server_version);
        if (!server_version.isEqualOrEarlierVersionOf(state.clientContext.getClientVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        /*
         * RFC 6347 This specification increases the cookie size limit to 255 bytes for greater
         * future flexibility. The limit remains 32 for previous versions of DTLS.
         */
        if (!ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(server_version) && cookie.length > 32)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return cookie;
    }

    protected void processNewSessionTicket(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);

        TlsProtocol.assertEmpty(buf);

        state.client.notifyNewSessionTicket(newSessionTicket);
    }

    protected Certificate processServerCertificate(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        Certificate serverCertificate = Certificate.parse(buf);

        TlsProtocol.assertEmpty(buf);

        state.keyExchange.processServerCertificate(serverCertificate);
        state.authentication = state.client.getAuthentication();
        state.authentication.notifyServerCertificate(serverCertificate);

        return serverCertificate;
    }

    protected void processServerHello(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        SecurityParameters securityParameters = state.clientContext.getSecurityParameters();

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        reportServerVersion(state, server_version);

        securityParameters.serverRandom = TlsUtils.readFully(32, buf);

        state.selectedSessionID = TlsUtils.readOpaque8(buf);
        if (state.selectedSessionID.length > 32)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        state.client.notifySessionID(state.selectedSessionID);

        state.selectedCipherSuite = TlsUtils.readUint16(buf);
        if (!Arrays.contains(state.offeredCipherSuites, state.selectedCipherSuite)
            || state.selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
            || state.selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            || !TlsUtils.isValidCipherSuiteForVersion(state.selectedCipherSuite, server_version))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        validateSelectedCipherSuite(state.selectedCipherSuite, AlertDescription.illegal_parameter);

        state.client.notifySelectedCipherSuite(state.selectedCipherSuite);

        state.selectedCompressionMethod = TlsUtils.readUint8(buf);
        if (!Arrays.contains(state.offeredCompressionMethods, state.selectedCompressionMethod))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        state.client.notifySelectedCompressionMethod(state.selectedCompressionMethod);

        /*
         * RFC3546 2.2 The extended server hello message format MAY be sent in place of the server
         * hello message when the client has requested extended functionality via the extended
         * client hello message specified in Section 2.1. ... Note that the extended server hello
         * message is only sent in response to an extended client hello message. This prevents the
         * possibility that the extended server hello message could "break" existing TLS 1.0
         * clients.
         */

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */

        // Integer -> byte[]
        Hashtable serverExtensions = TlsProtocol.readExtensions(buf);

        /*
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message. However, see RFC 5746 exception below. We always include
         * the SCSV, so an Extended Server Hello is always allowed.
         */
        if (serverExtensions != null)
        {
            Enumeration e = serverExtensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();

                /*
                 * RFC 5746 Note that sending a "renegotiation_info" extension in response to a
                 * ClientHello containing only the SCSV is an explicit exception to the prohibition
                 * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                 * only allowed because the client is signaling its willingness to receive the
                 * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. TLS implementations
                 * MUST continue to comply with Section 7.4.1.4 for all other extensions.
                 */
                if (!extType.equals(TlsProtocol.EXT_RenegotiationInfo)
                    && null == TlsUtils.getExtensionData(state.clientExtensions, extType))
                {
                    /*
                     * RFC 3546 2.3 Note that for all extension types (including those defined in
                     * future), the extension type MUST NOT appear in the extended server hello
                     * unless the same extension type appeared in the corresponding client hello.
                     * Thus clients MUST abort the handshake if they receive an extension type in
                     * the extended server hello that they did not request in the associated
                     * (extended) client hello.
                     */
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);
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
                byte[] renegExtData = (byte[])serverExtensions.get(TlsProtocol.EXT_RenegotiationInfo);
                if (renegExtData != null)
                {
                    /*
                     * If the extension is present, set the secure_renegotiation flag to TRUE. The
                     * client MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                     * handshake_failure alert).
                     */
                    state.secure_renegotiation = true;

                    if (!Arrays.constantTimeAreEqual(renegExtData,
                        TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                    }
                }
            }

            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(serverExtensions);

            state.maxFragmentLength = evaluateMaxFragmentLengthExtension(state.clientExtensions, serverExtensions,
                AlertDescription.illegal_parameter);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(serverExtensions);

            state.allowCertificateStatus = TlsUtils.hasExpectedEmptyExtensionData(serverExtensions,
                TlsExtensionsUtils.EXT_status_request, AlertDescription.illegal_parameter);

            state.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(serverExtensions,
                TlsProtocol.EXT_SessionTicket, AlertDescription.illegal_parameter);
        }

        state.client.notifySecureRenegotiation(state.secure_renegotiation);

        if (state.clientExtensions != null)
        {
            state.client.processServerExtensions(serverExtensions);
        }
    }

    protected void processServerKeyExchange(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        state.keyExchange.processServerKeyExchange(buf);

        TlsProtocol.assertEmpty(buf);
    }

    protected void processServerSupplementalData(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        Vector serverSupplementalData = TlsProtocol.readSupplementalDataMessage(buf);
        state.client.processServerSupplementalData(serverSupplementalData);
    }

    protected void reportServerVersion(ClientHandshakeState state, ProtocolVersion server_version)
        throws IOException
    {
        TlsClientContextImpl clientContext = state.clientContext;
        ProtocolVersion currentServerVersion = clientContext.getServerVersion();
        if (null == currentServerVersion)
        {
            clientContext.setServerVersion(server_version);
            state.client.notifyServerVersion(server_version);
        }
        else if (!currentServerVersion.equals(server_version))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    protected static byte[] patchClientHelloWithCookie(byte[] clientHelloBody, byte[] cookie)
        throws IOException
    {
        int sessionIDPos = 34;
        int sessionIDLength = TlsUtils.readUint8(clientHelloBody, sessionIDPos);

        int cookieLengthPos = sessionIDPos + 1 + sessionIDLength;
        int cookiePos = cookieLengthPos + 1;

        byte[] patched = new byte[clientHelloBody.length + cookie.length];
        System.arraycopy(clientHelloBody, 0, patched, 0, cookieLengthPos);
        TlsUtils.checkUint8(cookie.length);
        TlsUtils.writeUint8(cookie.length, patched, cookieLengthPos);
        System.arraycopy(cookie, 0, patched, cookiePos, cookie.length);
        System.arraycopy(clientHelloBody, cookiePos, patched, cookiePos + cookie.length, clientHelloBody.length
            - cookiePos);

        return patched;
    }

    protected static class ClientHandshakeState
    {
        TlsClient client = null;
        TlsClientContextImpl clientContext = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        int[] offeredCipherSuites = null;
        short[] offeredCompressionMethods = null;
        Hashtable clientExtensions = null;
        byte[] selectedSessionID = null;
        int selectedCipherSuite = -1;
        short selectedCompressionMethod = -1;
        boolean secure_renegotiation = false;
        short maxFragmentLength = -1;
        boolean allowCertificateStatus = false;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        TlsAuthentication authentication = null;
        CertificateStatus certificateStatus = null;
        CertificateRequest certificateRequest = null;
        TlsCredentials clientCredentials = null;
    }
}
