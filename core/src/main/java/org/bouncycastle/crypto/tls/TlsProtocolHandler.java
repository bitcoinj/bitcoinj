package org.bouncycastle.crypto.tls;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * @deprecated use TlsClientProtocol instead
 */
public class TlsProtocolHandler
    extends TlsClientProtocol
{
    public TlsProtocolHandler(InputStream is, OutputStream os)
    {
        super(is, os);
    }

    public TlsProtocolHandler(InputStream is, OutputStream os, SecureRandom sr)
    {
        super(is, os, sr);
    }
}
