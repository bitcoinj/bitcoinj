package org.bouncycastle.crypto.tls;

public abstract class AbstractTlsSignerCredentials
    extends AbstractTlsCredentials
    implements TlsSignerCredentials
{
    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        throw new IllegalStateException("TlsSignerCredentials implementation does not support (D)TLS 1.2+");
    }
}
