package org.bouncycastle.pqc.crypto.ntru;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.text.DecimalFormat;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * A set of parameters for NtruSign. Several predefined parameter sets are available and new ones can be created as well.
 */
public class NTRUSigningKeyGenerationParameters
    extends KeyGenerationParameters
    implements Cloneable
{   
    public static final int BASIS_TYPE_STANDARD = 0;
    public static final int BASIS_TYPE_TRANSPOSE = 1;

    public static final int KEY_GEN_ALG_RESULTANT = 0;
    public static final int KEY_GEN_ALG_FLOAT = 1;
    
    /**
     * Gives 128 bits of security
     */
    public static final NTRUSigningKeyGenerationParameters APR2011_439 = new NTRUSigningKeyGenerationParameters(439, 2048, 146, 1, BASIS_TYPE_TRANSPOSE, 0.165, 400, 280, false, true, KEY_GEN_ALG_RESULTANT, new SHA256Digest());

    /**
     * Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials
     */
    public static final NTRUSigningKeyGenerationParameters APR2011_439_PROD = new NTRUSigningKeyGenerationParameters(439, 2048, 9, 8, 5, 1, BASIS_TYPE_TRANSPOSE, 0.165, 400, 280, false, true, KEY_GEN_ALG_RESULTANT, new SHA256Digest());

    /**
     * Gives 256 bits of security
     */
    public static final NTRUSigningKeyGenerationParameters APR2011_743 = new NTRUSigningKeyGenerationParameters(743, 2048, 248, 1, BASIS_TYPE_TRANSPOSE, 0.127, 405, 360, true, false, KEY_GEN_ALG_RESULTANT, new SHA512Digest());

    /**
     * Like <code>APR2011_439</code>, this parameter set gives 256 bits of security but uses product-form polynomials
     */
    public static final NTRUSigningKeyGenerationParameters APR2011_743_PROD = new NTRUSigningKeyGenerationParameters(743, 2048, 11, 11, 15, 1, BASIS_TYPE_TRANSPOSE, 0.127, 405, 360, true, false, KEY_GEN_ALG_RESULTANT, new SHA512Digest());

    /**
     * Generates key pairs quickly. Use for testing only.
     */
    public static final NTRUSigningKeyGenerationParameters TEST157 = new NTRUSigningKeyGenerationParameters(157, 256, 29, 1, BASIS_TYPE_TRANSPOSE, 0.38, 200, 80, false, false, KEY_GEN_ALG_RESULTANT, new SHA256Digest());
    /**
     * Generates key pairs quickly. Use for testing only.
     */
    public static final NTRUSigningKeyGenerationParameters TEST157_PROD = new NTRUSigningKeyGenerationParameters(157, 256, 5, 5, 8, 1, BASIS_TYPE_TRANSPOSE, 0.38, 200, 80, false, false, KEY_GEN_ALG_RESULTANT, new SHA256Digest());


    public int N;
    public int q;
    public int d, d1, d2, d3, B;
    double beta;
    public double betaSq;
    double normBound;
    public double normBoundSq;
    public int signFailTolerance = 100;
    double keyNormBound;
    public double keyNormBoundSq;
    public boolean primeCheck;   // true if N and 2N+1 are prime
    public int basisType;
    int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
    public boolean sparse;   // whether to treat ternary polynomials as sparsely populated
    public int keyGenAlg;
    public Digest hashAlg;
    public int polyType;

    /**
     * Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
     *
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param d            number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param B            number of perturbations
     * @param basisType    whether to use the standard or transpose lattice
     * @param beta         balancing factor for the transpose lattice
     * @param normBound    maximum norm for valid signatures
     * @param keyNormBound maximum norm for the ploynomials <code>F</code> and <code>G</code>
     * @param primeCheck   whether <code>2N+1</code> is prime
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial} vs {@link org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial})
     * @param keyGenAlg    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography.
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public NTRUSigningKeyGenerationParameters(int N, int q, int d, int B, int basisType, double beta, double normBound, double keyNormBound, boolean primeCheck, boolean sparse, int keyGenAlg, Digest hashAlg)
    {
        super(new SecureRandom(), N);
        this.N = N;
        this.q = q;
        this.d = d;
        this.B = B;
        this.basisType = basisType;
        this.beta = beta;
        this.normBound = normBound;
        this.keyNormBound = keyNormBound;
        this.primeCheck = primeCheck;
        this.sparse = sparse;
        this.keyGenAlg = keyGenAlg;
        this.hashAlg = hashAlg;
        polyType = NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE;
        init();
    }

    /**
     * Constructs a parameter set that uses product-form private keys (i.e. <code>polyType=PRODUCT</code>).
     *
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param d1           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param d2           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param d3           number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param B            number of perturbations
     * @param basisType    whether to use the standard or transpose lattice
     * @param beta         balancing factor for the transpose lattice
     * @param normBound    maximum norm for valid signatures
     * @param keyNormBound maximum norm for the ploynomials <code>F</code> and <code>G</code>
     * @param primeCheck   whether <code>2N+1</code> is prime
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial} vs {@link org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial})
     * @param keyGenAlg    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography.
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public NTRUSigningKeyGenerationParameters(int N, int q, int d1, int d2, int d3, int B, int basisType, double beta, double normBound, double keyNormBound, boolean primeCheck, boolean sparse, int keyGenAlg, Digest hashAlg)
    {
        super(new SecureRandom(), N);
        this.N = N;
        this.q = q;
        this.d1 = d1;
        this.d2 = d2;
        this.d3 = d3;
        this.B = B;
        this.basisType = basisType;
        this.beta = beta;
        this.normBound = normBound;
        this.keyNormBound = keyNormBound;
        this.primeCheck = primeCheck;
        this.sparse = sparse;
        this.keyGenAlg = keyGenAlg;
        this.hashAlg = hashAlg;
        polyType = NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT;
        init();
    }

    private void init()
    {
        betaSq = beta * beta;
        normBoundSq = normBound * normBound;
        keyNormBoundSq = keyNormBound * keyNormBound;
    }

    /**
     * Reads a parameter set from an input stream.
     *
     * @param is an input stream
     * @throws java.io.IOException
     */
    public NTRUSigningKeyGenerationParameters(InputStream is)
        throws IOException
    {
        super(new SecureRandom(), 0);     // TODO:
        DataInputStream dis = new DataInputStream(is);
        N = dis.readInt();
        q = dis.readInt();
        d = dis.readInt();
        d1 = dis.readInt();
        d2 = dis.readInt();
        d3 = dis.readInt();
        B = dis.readInt();
        basisType = dis.readInt();
        beta = dis.readDouble();
        normBound = dis.readDouble();
        keyNormBound = dis.readDouble();
        signFailTolerance = dis.readInt();
        primeCheck = dis.readBoolean();
        sparse = dis.readBoolean();
        bitsF = dis.readInt();
        keyGenAlg = dis.read();
        String alg = dis.readUTF();
        if ("SHA-512".equals(alg))
        {
            hashAlg = new SHA512Digest();
        }
        else if ("SHA-256".equals(alg))
        {
            hashAlg = new SHA256Digest();
        }
        polyType = dis.read();
        init();
    }

    /**
     * Writes the parameter set to an output stream
     *
     * @param os an output stream
     * @throws java.io.IOException
     */
    public void writeTo(OutputStream os)
        throws IOException
    {
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(N);
        dos.writeInt(q);
        dos.writeInt(d);
        dos.writeInt(d1);
        dos.writeInt(d2);
        dos.writeInt(d3);
        dos.writeInt(B);
        dos.writeInt(basisType);
        dos.writeDouble(beta);
        dos.writeDouble(normBound);
        dos.writeDouble(keyNormBound);
        dos.writeInt(signFailTolerance);
        dos.writeBoolean(primeCheck);
        dos.writeBoolean(sparse);
        dos.writeInt(bitsF);
        dos.write(keyGenAlg);
        dos.writeUTF(hashAlg.getAlgorithmName());
        dos.write(polyType);
    }

    public NTRUSigningParameters getSigningParameters()
    {
        return new NTRUSigningParameters(N, q, d, B, beta, normBound, hashAlg);
    }

    public NTRUSigningKeyGenerationParameters clone()
    {
        if (polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
        {
            return new NTRUSigningKeyGenerationParameters(N, q, d, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
        }
        else
        {
            return new NTRUSigningKeyGenerationParameters(N, q, d1, d2, d3, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
        }
    }

    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + B;
        result = prime * result + N;
        result = prime * result + basisType;
        long temp;
        temp = Double.doubleToLongBits(beta);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(betaSq);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        result = prime * result + bitsF;
        result = prime * result + d;
        result = prime * result + d1;
        result = prime * result + d2;
        result = prime * result + d3;
        result = prime * result + ((hashAlg == null) ? 0 : hashAlg.getAlgorithmName().hashCode());
        result = prime * result + keyGenAlg;
        temp = Double.doubleToLongBits(keyNormBound);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(keyNormBoundSq);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(normBound);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(normBoundSq);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        result = prime * result + polyType;
        result = prime * result + (primeCheck ? 1231 : 1237);
        result = prime * result + q;
        result = prime * result + signFailTolerance;
        result = prime * result + (sparse ? 1231 : 1237);
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
        if (!(obj instanceof NTRUSigningKeyGenerationParameters))
        {
            return false;
        }
        NTRUSigningKeyGenerationParameters other = (NTRUSigningKeyGenerationParameters)obj;
        if (B != other.B)
        {
            return false;
        }
        if (N != other.N)
        {
            return false;
        }
        if (basisType != other.basisType)
        {
            return false;
        }
        if (Double.doubleToLongBits(beta) != Double.doubleToLongBits(other.beta))
        {
            return false;
        }
        if (Double.doubleToLongBits(betaSq) != Double.doubleToLongBits(other.betaSq))
        {
            return false;
        }
        if (bitsF != other.bitsF)
        {
            return false;
        }
        if (d != other.d)
        {
            return false;
        }
        if (d1 != other.d1)
        {
            return false;
        }
        if (d2 != other.d2)
        {
            return false;
        }
        if (d3 != other.d3)
        {
            return false;
        }
        if (hashAlg == null)
        {
            if (other.hashAlg != null)
            {
                return false;
            }
        }
        else if (!hashAlg.getAlgorithmName().equals(other.hashAlg.getAlgorithmName()))
        {
            return false;
        }
        if (keyGenAlg != other.keyGenAlg)
        {
            return false;
        }
        if (Double.doubleToLongBits(keyNormBound) != Double.doubleToLongBits(other.keyNormBound))
        {
            return false;
        }
        if (Double.doubleToLongBits(keyNormBoundSq) != Double.doubleToLongBits(other.keyNormBoundSq))
        {
            return false;
        }
        if (Double.doubleToLongBits(normBound) != Double.doubleToLongBits(other.normBound))
        {
            return false;
        }
        if (Double.doubleToLongBits(normBoundSq) != Double.doubleToLongBits(other.normBoundSq))
        {
            return false;
        }
        if (polyType != other.polyType)
        {
            return false;
        }
        if (primeCheck != other.primeCheck)
        {
            return false;
        }
        if (q != other.q)
        {
            return false;
        }
        if (signFailTolerance != other.signFailTolerance)
        {
            return false;
        }
        if (sparse != other.sparse)
        {
            return false;
        }
        return true;
    }

    public String toString()
    {
        DecimalFormat format = new DecimalFormat("0.00");

        StringBuilder output = new StringBuilder("SignatureParameters(N=" + N + " q=" + q);
        if (polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE)
        {
            output.append(" polyType=SIMPLE d=" + d);
        }
        else
        {
            output.append(" polyType=PRODUCT d1=" + d1 + " d2=" + d2 + " d3=" + d3);
        }
        output.append(" B=" + B + " basisType=" + basisType + " beta=" + format.format(beta) +
            " normBound=" + format.format(normBound) + " keyNormBound=" + format.format(keyNormBound) +
            " prime=" + primeCheck + " sparse=" + sparse + " keyGenAlg=" + keyGenAlg + " hashAlg=" + hashAlg + ")");
        return output.toString();
    }
}
