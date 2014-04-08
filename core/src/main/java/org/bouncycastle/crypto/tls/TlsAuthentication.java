package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface TlsAuthentication
{
    /**
     * Called by the protocol handler to report the server certificate
     * Note: this method is responsible for certificate verification and validation
     *
     * @param serverCertificate the server certificate received
     * @throws IOException
     */
    void notifyServerCertificate(Certificate serverCertificate)
        throws IOException;

    /**
     * Return client credentials in response to server's certificate request
     *
     * @param certificateRequest details of the certificate request
     * @return a TlsCredentials object or null for no client authentication
     * @throws IOException
     */
    TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
        throws IOException;
}
