package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public interface TlsServer
    extends TlsPeer
{
    void init(TlsServerContext context);

    void notifyClientVersion(ProtocolVersion clientVersion) throws IOException;

    void notifyOfferedCipherSuites(int[] offeredCipherSuites)
        throws IOException;

    void notifyOfferedCompressionMethods(short[] offeredCompressionMethods)
        throws IOException;

    // Hashtable is (Integer -> byte[])
    void processClientExtensions(Hashtable clientExtensions)
        throws IOException;

    ProtocolVersion getServerVersion()
        throws IOException;

    int getSelectedCipherSuite()
        throws IOException;

    short getSelectedCompressionMethod()
        throws IOException;

    // Hashtable is (Integer -> byte[])
    Hashtable getServerExtensions()
        throws IOException;

    // Vector is (SupplementalDataEntry)
    Vector getServerSupplementalData()
        throws IOException;

    TlsCredentials getCredentials()
        throws IOException;

    /**
     * This method will be called (only) if the server included an extension of type
     * "status_request" with empty "extension_data" in the extended server hello. See <i>RFC 3546
     * 3.6. Certificate Status Request</i>. If a non-null {@link CertificateStatus} is returned, it
     * is sent to the client as a handshake message of type "certificate_status".
     * 
     * @return A {@link CertificateStatus} to be sent to the client (or null for none).
     * @throws IOException
     */
    CertificateStatus getCertificateStatus()
        throws IOException;

    TlsKeyExchange getKeyExchange()
        throws IOException;

    CertificateRequest getCertificateRequest()
        throws IOException;

    // Vector is (SupplementalDataEntry)
    void processClientSupplementalData(Vector clientSupplementalData)
        throws IOException;

    /**
     * Called by the protocol handler to report the client certificate, only if
     * {@link #getCertificateRequest()} returned non-null.
     * 
     * Note: this method is responsible for certificate verification and validation.
     * 
     * @param clientCertificate
     *            the effective client certificate (may be an empty chain).
     * @throws IOException
     */
    void notifyClientCertificate(Certificate clientCertificate)
        throws IOException;

    /**
     * RFC 5077 3.3. NewSessionTicket Handshake Message.
     * <p>
     * This method will be called (only) if a NewSessionTicket extension was sent by the server. See
     * <i>RFC 5077 4. Recommended Ticket Construction</i> for recommended format and protection.
     *
     * @return The ticket.
     * @throws IOException
     */
    NewSessionTicket getNewSessionTicket()
        throws IOException;
}
