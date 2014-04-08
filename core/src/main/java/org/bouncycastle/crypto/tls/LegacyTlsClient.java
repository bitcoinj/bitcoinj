package org.bouncycastle.crypto.tls;

import java.io.IOException;

/**
 * A temporary class to use LegacyTlsAuthentication
 *
 * @deprecated
 */
public class LegacyTlsClient
    extends DefaultTlsClient
{
    /**
     * @deprecated
     */
    protected CertificateVerifyer verifyer;

    /**
     * @deprecated
     */
    public LegacyTlsClient(CertificateVerifyer verifyer)
    {
        super();

        this.verifyer = verifyer;
    }

    public TlsAuthentication getAuthentication()
        throws IOException
    {
        return new LegacyTlsAuthentication(verifyer);
    }
}
