package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * RFC 5246 7.4.1.4.1
 */
public class SignatureAndHashAlgorithm
{
    protected short hash;
    protected short signature;

    /**
     * @param hash      {@link HashAlgorithm}
     * @param signature {@link SignatureAlgorithm}
     */
    public SignatureAndHashAlgorithm(short hash, short signature)
    {
        if (!TlsUtils.isValidUint8(hash))
        {
            throw new IllegalArgumentException("'hash' should be a uint8");
        }
        if (!TlsUtils.isValidUint8(signature))
        {
            throw new IllegalArgumentException("'signature' should be a uint8");
        }
        if (signature == SignatureAlgorithm.anonymous)
        {
            throw new IllegalArgumentException("'signature' MUST NOT be \"anonymous\"");
        }

        this.hash = hash;
        this.signature = signature;
    }

    /**
     * @return {@link HashAlgorithm}
     */
    public short getHash()
    {
        return hash;
    }

    /**
     * @return {@link SignatureAlgorithm}
     */
    public short getSignature()
    {
        return signature;
    }

    public boolean equals(Object obj)
    {
        if (!(obj instanceof SignatureAndHashAlgorithm))
        {
            return false;
        }
        SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm)obj;
        return other.getHash() == getHash() && other.getSignature() == getSignature();
    }

    public int hashCode()
    {
        return (getHash() << 16) | getSignature();
    }

    /**
     * Encode this {@link SignatureAndHashAlgorithm} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        TlsUtils.writeUint8(getHash(), output);
        TlsUtils.writeUint8(getSignature(), output);
    }

    /**
     * Parse a {@link SignatureAndHashAlgorithm} from an {@link InputStream}.
     *
     * @param input the {@link InputStream} to parse from.
     * @return a {@link SignatureAndHashAlgorithm} object.
     * @throws IOException
     */
    public static SignatureAndHashAlgorithm parse(InputStream input)
        throws IOException
    {
        short hash = TlsUtils.readUint8(input);
        short signature = TlsUtils.readUint8(input);
        return new SignatureAndHashAlgorithm(hash, signature);
    }
}
