package org.bouncycastle.crypto.tls;

import java.io.IOException;

/**
 * A temporary class to wrap old CertificateVerifyer stuff for new TlsAuthentication
 *
 * @deprecated
 */
public class LegacyTlsAuthentication
    extends ServerOnlyTlsAuthentication
{
    protected CertificateVerifyer verifyer;

    public LegacyTlsAuthentication(CertificateVerifyer verifyer)
    {
        this.verifyer = verifyer;
    }

    public void notifyServerCertificate(Certificate serverCertificate)
        throws IOException
    {
        if (!this.verifyer.isValid(serverCertificate.getCertificateList()))
        {
            throw new TlsFatalAlert(AlertDescription.user_canceled);
        }
    }
}
