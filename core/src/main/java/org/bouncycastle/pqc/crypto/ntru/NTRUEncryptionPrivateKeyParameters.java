package org.bouncycastle.pqc.crypto.ntru;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;

/**
 * A NtruEncrypt private key is essentially a polynomial named <code>f</code>
 * which takes different forms depending on whether product-form polynomials are used,
 * and on <code>fastP</code><br>
 * The inverse of <code>f</code> modulo <code>p</code> is precomputed on initialization.
 */
public class NTRUEncryptionPrivateKeyParameters
    extends NTRUEncryptionKeyParameters
{
    public Polynomial t;
    public IntegerPolynomial fp;
    public IntegerPolynomial h;

    /**
     * Constructs a new private key from a polynomial
     *
     * @param h the public polynomial for the key.
     * @param t      the polynomial which determines the key: if <code>fastFp=true</code>, <code>f=1+3t</code>; otherwise, <code>f=t</code>
     * @param fp     the inverse of <code>f</code>
     * @param params the NtruEncrypt parameters to use
     */
    public NTRUEncryptionPrivateKeyParameters(IntegerPolynomial h, Polynomial t, IntegerPolynomial fp, NTRUEncryptionParameters params)
    {
        super(true, params);

        this.h = h;
        this.t = t;
        this.fp = fp;
    }

    /**
     * Converts a byte array to a polynomial <code>f</code> and constructs a new private key
     *
     * @param b      an encoded polynomial
     * @param params the NtruEncrypt parameters to use
     * @see #getEncoded()
     */
    public NTRUEncryptionPrivateKeyParameters(byte[] b, NTRUEncryptionParameters params)
        throws IOException
    {
        this(new ByteArrayInputStream(b), params);
    }

    /**
     * Reads a polynomial <code>f</code> from an input stream and constructs a new private key
     *
     * @param is     an input stream
     * @param params the NtruEncrypt parameters to use
     * @see #writeTo(OutputStream)
     */
    public NTRUEncryptionPrivateKeyParameters(InputStream is, NTRUEncryptionParameters params)
        throws IOException
    {
        super(true, params);

        if (params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT)
        {
            int N = params.N;
            int df1 = params.df1;
            int df2 = params.df2;
            int df3Ones = params.df3;
            int df3NegOnes = params.fastFp ? params.df3 : params.df3 - 1;
            h = IntegerPolynomial.fromBinary(is, params.N, params.q);
            t = ProductFormPolynomial.fromBinary(is, N, df1, df2, df3Ones, df3NegOnes);
        }
        else
        {
            h = IntegerPolynomial.fromBinary(is, params.N, params.q);
            IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(is, params.N);
            t = params.sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
        }

        init();
    }

    /**
     * Initializes <code>fp</code> from t.
     */
    private void init()
    {
        if (params.fastFp)
        {
            fp = new IntegerPolynomial(params.N);
            fp.coeffs[0] = 1;
        }
        else
        {
            fp = t.toIntegerPolynomial().invertF3();
        }
    }

    /**
     * Converts the key to a byte array
     *
     * @return the encoded key
     * @see #NTRUEncryptionPrivateKeyParameters(byte[], NTRUEncryptionParameters)
     */
    public byte[] getEncoded()
    {
        byte[] hBytes = h.toBinary(params.q);
        byte[] tBytes;

        if (t instanceof ProductFormPolynomial)
        {
            tBytes = ((ProductFormPolynomial)t).toBinary();
        }
        else
        {
            tBytes = t.toIntegerPolynomial().toBinary3Tight();
        }

        byte[] res = new byte[hBytes.length + tBytes.length];

        System.arraycopy(hBytes, 0, res, 0, hBytes.length);
        System.arraycopy(tBytes, 0, res, hBytes.length, tBytes.length);

        return res;
    }

    /**
     * Writes the key to an output stream
     *
     * @param os an output stream
     * @throws IOException
     * @see #NTRUEncryptionPrivateKeyParameters(InputStream, NTRUEncryptionParameters)
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
        result = prime * result + ((params == null) ? 0 : params.hashCode());
        result = prime * result + ((t == null) ? 0 : t.hashCode());
        result = prime * result + ((h == null) ? 0 : h.hashCode());
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
        if (!(obj instanceof NTRUEncryptionPrivateKeyParameters))
        {
            return false;
        }
        NTRUEncryptionPrivateKeyParameters other = (NTRUEncryptionPrivateKeyParameters)obj;
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
        if (t == null)
        {
            if (other.t != null)
            {
                return false;
            }
        }
        else if (!t.equals(other.t))
        {
            return false;
        }
        if (!h.equals(other.h))
        {
            return false;
        }
        return true;
    }
}