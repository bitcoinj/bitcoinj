package org.bouncycastle.crypto.tls;

/*
 * RFC 3546 3.3.
 */
public class CertChainType
{
    public static final short individual_certs = 0;
    public static final short pkipath = 1;

    public static boolean isValid(short certChainType)
    {
        return certChainType >= individual_certs && certChainType <= pkipath;
    }
}
