package org.bouncycastle.pqc.crypto.ntru;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;

/**
 * A NtruSign private key comprises one or more {@link NTRUSigningPrivateKeyParameters.Basis} of three polynomials each,
 * except the zeroth basis for which <code>h</code> is undefined.
 */
public class NTRUSigningPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private List<Basis> bases;
    private NTRUSigningPublicKeyParameters publicKey;

    /**
     * Constructs a new private key from a byte array
     *
     * @param b      an encoded private key
     * @param params the NtruSign parameters to use
     */
    public NTRUSigningPrivateKeyParameters(byte[] b, NTRUSigningKeyGenerationParameters params)
        throws IOException
    {
        this(new ByteArrayInputStream(b), params);
    }

    /**
     * Constructs a new private key from an input stream
     *
     * @param is     an input stream
     * @param params the NtruSign parameters to use
     */
    public NTRUSigningPrivateKeyParameters(InputStream is, NTRUSigningKeyGenerationParameters params)
        throws IOException
    {
        super(true);
        bases = new ArrayList<Basis>();
        for (int i = 0; i <= params.B; i++)
        // include a public key h[i] in all bases except for the first one
        {
            add(new Basis(is, params, i != 0));
        }
        publicKey = new NTRUSigningPublicKeyParameters(is, params.getSigningParameters());
    }

    public NTRUSigningPrivateKeyParameters(List<Basis> bases, NTRUSigningPublicKeyParameters publicKey)
    {
        super(true);
        this.bases = new ArrayList<Basis>(bases);
        this.publicKey = publicKey;
    }

    /**
     * Adds a basis to the key.
     *
     * @param b a NtruSign basis
     */
    private void add(Basis b)
    {
        bases.add(b);
    }

    /**
     * Returns the <code>i</code>-th basis
     *
     * @param i the index
     * @return the basis at index <code>i</code>
     */
    public Basis getBasis(int i)
    {
        return bases.get(i);
    }

    public NTRUSigningPublicKeyParameters getPublicKey()
    {
        return publicKey;
    }

    /**
     * Converts the key to a byte array
     *
     * @return the encoded key
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for (int i = 0; i < bases.size(); i++)
        {
            // all bases except for the first one contain a public key
            bases.get(i).encode(os, i != 0);
        }

        os.write(publicKey.getEncoded());

        return os.toByteArray();
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
        result = prime * result + ((bases == null) ? 0 : bases.hashCode());
        for (Basis basis : bases)
        {
            result += basis.hashCode();
        }
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
        NTRUSigningPrivateKeyParameters other = (NTRUSigningPrivateKeyParameters)obj;
        if (bases == null)
        {
            if (other.bases != null)
            {
                return false;
            }
        }
        if (bases.size() != other.bases.size())
        {
            return false;
        }
        for (int i = 0; i < bases.size(); i++)
        {
            Basis basis1 = bases.get(i);
            Basis basis2 = other.bases.get(i);
            if (!basis1.f.equals(basis2.f))
            {
                return false;
            }
            if (!basis1.fPrime.equals(basis2.fPrime))
            {
                return false;
            }
            if (i != 0 && !basis1.h.equals(basis2.h))   // don't compare h for the 0th basis
            {
                return false;
            }
            if (!basis1.params.equals(basis2.params))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * A NtruSign basis. Contains three polynomials <code>f, f', h</code>.
     */
    public static class Basis
    {
        public Polynomial f;
        public Polynomial fPrime;
        public IntegerPolynomial h;
        NTRUSigningKeyGenerationParameters params;

        /**
         * Constructs a new basis from polynomials <code>f, f', h</code>.
         *
         * @param f
         * @param fPrime
         * @param h
         * @param params NtruSign parameters
         */
        protected Basis(Polynomial f, Polynomial fPrime, IntegerPolynomial h, NTRUSigningKeyGenerationParameters params)
        {
            this.f = f;
            this.fPrime = fPrime;
            this.h = h;
            this.params = params;
        }

        /**
         * Reads a basis from an input stream and constructs a new basis.
         *
         * @param is        an input stream
         * @param params    NtruSign parameters
         * @param include_h whether to read the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
         */
        Basis(InputStream is, NTRUSigningKeyGenerationParameters params, boolean include_h)
            throws IOException
        {
            int N = params.N;
            int q = params.q;
            int d1 = params.d1;
            int d2 = params.d2;
            int d3 = params.d3;
            boolean sparse = params.sparse;
            this.params = params;

            if (params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT)
            {
                f = ProductFormPolynomial.fromBinary(is, N, d1, d2, d3 + 1, d3);
            }
            else
            {
                IntegerPolynomial fInt = IntegerPolynomial.fromBinary3Tight(is, N);
                f = sparse ? new SparseTernaryPolynomial(fInt) : new DenseTernaryPolynomial(fInt);
            }

            if (params.basisType == NTRUSigningKeyGenerationParameters.BASIS_TYPE_STANDARD)
            {
                IntegerPolynomial fPrimeInt = IntegerPolynomial.fromBinary(is, N, q);
                for (int i = 0; i < fPrimeInt.coeffs.length; i++)
                {
                    fPrimeInt.coeffs[i] -= q / 2;
                }
                fPrime = fPrimeInt;
            }
            else if (params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT)
            {
                fPrime = ProductFormPolynomial.fromBinary(is, N, d1, d2, d3 + 1, d3);
            }
            else
            {
                fPrime = IntegerPolynomial.fromBinary3Tight(is, N);
            }

            if (include_h)
            {
                h = IntegerPolynomial.fromBinary(is, N, q);
            }
        }

        /**
         * Writes the basis to an output stream
         *
         * @param os        an output stream
         * @param include_h whether to write the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
         * @throws IOException
         */
        void encode(OutputStream os, boolean include_h)
            throws IOException
        {
            int q = params.q;

            os.write(getEncoded(f));
            if (params.basisType == NTRUSigningKeyGenerationParameters.BASIS_TYPE_STANDARD)
            {
                IntegerPolynomial fPrimeInt = fPrime.toIntegerPolynomial();
                for (int i = 0; i < fPrimeInt.coeffs.length; i++)
                {
                    fPrimeInt.coeffs[i] += q / 2;
                }
                os.write(fPrimeInt.toBinary(q));
            }
            else
            {
                os.write(getEncoded(fPrime));
            }
            if (include_h)
            {
                os.write(h.toBinary(q));
            }
        }

        private byte[] getEncoded(Polynomial p)
        {
            if (p instanceof ProductFormPolynomial)
            {
                return ((ProductFormPolynomial)p).toBinary();
            }
            else
            {
                return p.toIntegerPolynomial().toBinary3Tight();
            }
        }

        @Override
        public int hashCode()
        {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((f == null) ? 0 : f.hashCode());
            result = prime * result + ((fPrime == null) ? 0 : fPrime.hashCode());
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
            if (!(obj instanceof Basis))
            {
                return false;
            }
            Basis other = (Basis)obj;
            if (f == null)
            {
                if (other.f != null)
                {
                    return false;
                }
            }
            else if (!f.equals(other.f))
            {
                return false;
            }
            if (fPrime == null)
            {
                if (other.fPrime != null)
                {
                    return false;
                }
            }
            else if (!fPrime.equals(other.fPrime))
            {
                return false;
            }
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
}