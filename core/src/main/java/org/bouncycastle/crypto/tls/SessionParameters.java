package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Arrays;

public final class SessionParameters
{
    public static final class Builder
    {
        private int cipherSuite = -1;
        private short compressionAlgorithm = -1;
        private byte[] masterSecret = null;
        private Certificate peerCertificate = null;
        private byte[] encodedServerExtensions = null;

        public Builder()
        {
        }

        public SessionParameters build()
        {
            validate(this.cipherSuite >= 0, "cipherSuite");
            validate(this.compressionAlgorithm >= 0, "compressionAlgorithm");
            validate(this.masterSecret != null, "masterSecret");
            return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret, peerCertificate,
                encodedServerExtensions);
        }

        public Builder setCipherSuite(int cipherSuite)
        {
            this.cipherSuite = cipherSuite;
            return this;
        }

        public Builder setCompressionAlgorithm(short compressionAlgorithm)
        {
            this.compressionAlgorithm = compressionAlgorithm;
            return this;
        }

        public Builder setMasterSecret(byte[] masterSecret)
        {
            this.masterSecret = masterSecret;
            return this;
        }

        public Builder setPeerCertificate(Certificate peerCertificate)
        {
            this.peerCertificate = peerCertificate;
            return this;
        }

        public Builder setServerExtensions(Hashtable serverExtensions)
            throws IOException
        {
            if (serverExtensions == null)
            {
                encodedServerExtensions = null;
            }
            else
            {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                TlsProtocol.writeExtensions(buf, serverExtensions);
                encodedServerExtensions = buf.toByteArray();
            }
            return this;
        }

        private void validate(boolean condition, String parameter)
        {
            if (!condition)
            {
                throw new IllegalStateException("Required session parameter '" + parameter + "' not configured");
            }
        }
    }

    private int cipherSuite;
    private short compressionAlgorithm;
    private byte[] masterSecret;
    private Certificate peerCertificate;
    private byte[] encodedServerExtensions;

    private SessionParameters(int cipherSuite, short compressionAlgorithm, byte[] masterSecret,
        Certificate peerCertificate, byte[] encodedServerExtensions)
    {
        this.cipherSuite = cipherSuite;
        this.compressionAlgorithm = compressionAlgorithm;
        this.masterSecret = Arrays.clone(masterSecret);
        this.peerCertificate = peerCertificate;
        this.encodedServerExtensions = encodedServerExtensions;
    }

    public void clear()
    {
        if (this.masterSecret != null)
        {
            Arrays.fill(this.masterSecret, (byte)0);
        }
    }

    public SessionParameters copy()
    {
        return new SessionParameters(cipherSuite, compressionAlgorithm, masterSecret, peerCertificate,
            encodedServerExtensions);
    }

    public int getCipherSuite()
    {
        return cipherSuite;
    }

    public short getCompressionAlgorithm()
    {
        return compressionAlgorithm;
    }

    public byte[] getMasterSecret()
    {
        return masterSecret;
    }

    public Certificate getPeerCertificate()
    {
        return peerCertificate;
    }

    public Hashtable readServerExtensions() throws IOException
    {
        if (encodedServerExtensions == null)
        {
            return null;
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(encodedServerExtensions);
        return TlsProtocol.readExtensions(buf);
    }
}
