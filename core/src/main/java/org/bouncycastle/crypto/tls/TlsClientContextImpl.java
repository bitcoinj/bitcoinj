package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

class TlsClientContextImpl
    extends AbstractTlsContext
    implements TlsClientContext
{
    TlsClientContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters)
    {
        super(secureRandom, securityParameters);
    }

    public boolean isServer()
    {
        return false;
    }
}
