package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class AbstractTlsCipherFactory
    implements TlsCipherFactory
{
    public TlsCipher createCipher(TlsContext context, int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
