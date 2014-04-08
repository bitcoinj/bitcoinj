package org.bouncycastle.pqc.crypto.ntru;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;

/**
 * A NtruEncrypt public key is essentially a polynomial named <code>h</code>.
 */
public class NTRUEncryptionPublicKeyParameters
    extends NTRUEncryptionKeyParameters
{
    public IntegerPolynomial h;

    /**
     * Constructs a new public key from a polynomial
     *
     * @param h      the polynomial <code>h</code> which determines the key
     * @param params the NtruEncrypt parameters to use
     */
    public NTRUEncryptionPublicKeyParameters(IntegerPolynomial h, NTRUEncryptionParameters params)
    {
        super(false, params);

        this.h = h;
    }

    /**
     * Converts a byte array to a polynomial <code>h</code> and constructs a new public key
     *
     * @param b      an encoded polynomial
     * @param params the NtruEncrypt parameters to use
     * @see #getEncoded()
     */
    public NTRUEncryptionPublicKeyParameters(byte[] b, NTRUEncryptionParameters params)
    {
        super(false, params);

        h = IntegerPolynomial.fromBinary(b, params.N, params.q);
    }

    /**
     * Reads a polynomial <code>h</code> from an input stream and constructs a new public key
     *
     * @param is     an input stream
     * @param params the NtruEncrypt parameters to use
     * @see #writeTo(OutputStream)
     */
    public NTRUEncryptionPublicKeyParameters(InputStream is, NTRUEncryptionParameters params)
        throws IOException
    {
        super(false, params);

        h = IntegerPolynomial.fromBinary(is, params.N, params.q);
    }

    /**
     * Converts the key to a byte array
     *
     * @return the encoded key
     * @see #NTRUEncryptionPublicKeyParameters(byte[], NTRUEncryptionParameters)
     */
    public byte[] getEncoded()
    {
        return h.toBinary(params.q);
    }

    /**
     * Writes the key to an output stream
     *
     * @param os an output stream
     * @throws IOException
     * @see #NTRUEncryptionPublicKeyParameters(InputStream, NTRUEncryptionParameters)
     */
    public void writeTo(OutputStream os)
        throws IOException
    {
        os.write(getEncoded());
    }

    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((h == null) ? 0 : h.hashCode());
        result = prime * result + ((params == null) ? 0 : params.hashCode());
        return result;
    }

    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (!(obj instanceof NTRUEncryptionPublicKeyParameters))
        {
            return false;
        }
        NTRUEncryptionPublicKeyParameters other = (NTRUEncryptionPublicKeyParameters)obj;
        if (h == null)
        {
            if (other.h != null)
            {
                return false;
            }
        }
        else if (!h.equals(other.h))
        {
            return false;
        }
        if (params == null)
        {
            if (other.params != null)
            {
                return false;
            }
        }
        else if (!params.equals(other.params))
        {
            return false;
        }
        return true;
    }
}