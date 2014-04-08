package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A generic interface for key exchange implementations in TLS 1.0/1.1.
 */
public interface TlsKeyExchange
{
    void init(TlsContext context);

    void skipServerCredentials()
        throws IOException;

    void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException;

    void processServerCertificate(Certificate serverCertificate)
        throws IOException;

    boolean requiresServerKeyExchange();

    byte[] generateServerKeyExchange()
        throws IOException;

    void skipServerKeyExchange()
        throws IOException;

    void processServerKeyExchange(InputStream input)
        throws IOException;

    void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException;

    void skipClientCredentials()
        throws IOException;

    void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException;

    void processClientCertificate(Certificate clientCertificate)
        throws IOException;

    void generateClientKeyExchange(OutputStream output)
        throws IOException;

    void processClientKeyExchange(InputStream input)
        throws IOException;

    byte[] generatePremasterSecret()
        throws IOException;
}
