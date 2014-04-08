package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

public abstract class AbstractTlsKeyExchange
    implements TlsKeyExchange
{
    protected int keyExchange;
    protected Vector supportedSignatureAlgorithms;

    protected TlsContext context;

    protected AbstractTlsKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms)
    {
        this.keyExchange = keyExchange;
        this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
    }

    public void init(TlsContext context)
    {
        this.context = context;

        ProtocolVersion clientVersion = context.getClientVersion();

        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
        {
            /*
             * RFC 5264 7.4.1.4.1. If the client does not send the signature_algorithms extension,
             * the server MUST do the following:
             * 
             * - If the negotiated key exchange algorithm is one of (RSA, DHE_RSA, DH_RSA, RSA_PSK,
             * ECDH_RSA, ECDHE_RSA), behave as if client had sent the value {sha1,rsa}.
             * 
             * - If the negotiated key exchange algorithm is one of (DHE_DSS, DH_DSS), behave as if
             * the client had sent the value {sha1,dsa}.
             * 
             * - If the negotiated key exchange algorithm is one of (ECDH_ECDSA, ECDHE_ECDSA),
             * behave as if the client had sent value {sha1,ecdsa}.
             */
            if (this.supportedSignatureAlgorithms == null)
            {
                switch (keyExchange)
                {
                case KeyExchangeAlgorithm.DH_DSS:
                case KeyExchangeAlgorithm.DHE_DSS:
                case KeyExchangeAlgorithm.SRP_DSS:
                {
                    this.supportedSignatureAlgorithms = TlsUtils.getDefaultDSSSignatureAlgorithms();
                    break;
                }

                case KeyExchangeAlgorithm.ECDH_ECDSA:
                case KeyExchangeAlgorithm.ECDHE_ECDSA:
                {
                    this.supportedSignatureAlgorithms = TlsUtils.getDefaultECDSASignatureAlgorithms();
                    break;
                }

                case KeyExchangeAlgorithm.DH_RSA:
                case KeyExchangeAlgorithm.DHE_RSA:
                case KeyExchangeAlgorithm.ECDH_RSA:
                case KeyExchangeAlgorithm.ECDHE_RSA:
                case KeyExchangeAlgorithm.RSA:
                case KeyExchangeAlgorithm.RSA_PSK:
                case KeyExchangeAlgorithm.SRP_RSA:
                {
                    this.supportedSignatureAlgorithms = TlsUtils.getDefaultRSASignatureAlgorithms();
                    break;
                }

                case KeyExchangeAlgorithm.DHE_PSK:
                case KeyExchangeAlgorithm.ECDHE_PSK:
                case KeyExchangeAlgorithm.PSK:
                case KeyExchangeAlgorithm.SRP:
                    break;

                default:
                    throw new IllegalStateException("unsupported key exchange algorithm");
                }
            }

        }
        else if (this.supportedSignatureAlgorithms != null)
        {
            throw new IllegalStateException("supported_signature_algorithms not allowed for " + clientVersion);
        }
    }

    public void processServerCertificate(Certificate serverCertificate)
        throws IOException
    {
        if (supportedSignatureAlgorithms == null)
        {
            /*
             * TODO RFC 2264 7.4.2. Unless otherwise specified, the signing algorithm for the
             * certificate must be the same as the algorithm for the certificate key.
             */
        }
        else
        {
            /*
             * TODO RFC 5264 7.4.2. If the client provided a "signature_algorithms" extension, then
             * all certificates provided by the server MUST be signed by a hash/signature algorithm
             * pair that appears in that extension.
             */
        }
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        processServerCertificate(serverCredentials.getCertificate());
    }

    public boolean requiresServerKeyExchange()
    {
        return false;
    }

    public byte[] generateServerKeyExchange()
        throws IOException
    {
        if (requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        return null;
    }

    public void skipServerKeyExchange()
        throws IOException
    {
        if (requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processServerKeyExchange(InputStream input)
        throws IOException
    {
        if (!requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void skipClientCredentials()
        throws IOException
    {
    }

    public void processClientCertificate(Certificate clientCertificate)
        throws IOException
    {
    }

    public void processClientKeyExchange(InputStream input)
        throws IOException
    {
        // Key exchange implementation MUST support client key exchange
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
