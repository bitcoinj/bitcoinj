package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface TlsSignerCredentials
    extends TlsCredentials
{
    byte[] generateCertificateSignature(byte[] hash)
        throws IOException;

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();
}
