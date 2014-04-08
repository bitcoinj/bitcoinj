package org.bouncycastle.pqc.crypto.ntru;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;

/**
 * A NtruSign public key is essentially a polynomial named <code>h</code>.
 */
public class NTRUSigningPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private NTRUSigningParameters params;
    public IntegerPolynomial h;

    /**
     * Constructs a new public key from a polynomial
     *
     * @param h      the polynomial <code>h</code> which determines the key
     * @param params the NtruSign parameters to use
     */
    public NTRUSigningPublicKeyParameters(IntegerPolynomial h, NTRUSigningParameters params)
    {
        super(false);
        this.h = h;
        this.params = params;
    }

    /**
     * Converts a byte array to a polynomial <code>h</code> and constructs a new public key
     *
     * @param b      an encoded polynomial
     * @param params the NtruSign parameters to use
     */
    public NTRUSigningPublicKeyParameters(byte[] b, NTRUSigningParameters params)
    {
        super(false);
        h = IntegerPolynomial.fromBinary(b, params.N, params.q);
        this.params = params;
    }

    /**
     * Reads a polynomial <code>h</code> from an input stream and constructs a new public key
     *
     * @param is     an input stream
     * @param params the NtruSign parameters to use
     */
    public NTRUSigningPublicKeyParameters(InputStream is, NTRUSigningParameters params)
        throws IOException
    {
        super(false);
        h = IntegerPolynomial.fromBinary(is, params.N, params.q);
        this.params = params;
    }


    /**
     * Converts the key to a byte array
     *
     * @return the encoded key
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
     */
    public void writeTo(OutputStream os)
        throws IOException
    {
        os.write(getEncoded());
    }

    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((h == null) ? 0 : h.hashCode());
        result = prime * result + ((params == null) ? 0 : params.hashCode());
        return result;
    }

    @Override
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
        if (getClass() != obj.getClass())
        {
            return false;
        }
        NTRUSigningPublicKeyParameters other = (NTRUSigningPublicKeyParameters)obj;
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