package org.bouncycastle.pqc.crypto.ntru;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DecimalFormat;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * A set of parameters for NtruSign. Several predefined parameter sets are available and new ones can be created as well.
 */
public class NTRUSigningParameters
    implements Cloneable
{
    public int N;
    public int q;
    public int d, d1, d2, d3, B;
    double beta;
    public double betaSq;
    double normBound;
    public double normBoundSq;
    public int signFailTolerance = 100;
    int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
    public Digest hashAlg;

    /**
     * Constructs a parameter set that uses ternary private keys (i.e. <code>polyType=SIMPLE</code>).
     *
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param d            number of -1's in the private polynomials <code>f</code> and <code>g</code>
     * @param B            number of perturbations
     * @param beta         balancing factor for the transpose lattice
     * @param normBound    maximum norm for valid signatures
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public NTRUSigningParameters(int N, int q, int d, int B, double beta, double normBound, Digest hashAlg)
    {
        this.N = N;
        this.q = q;
        this.d = d;
        this.B = B;
        this.beta = beta;
        this.normBound = normBound;
        this.hashAlg = hashAlg;
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
     * @param beta         balancing factor for the transpose lattice
     * @param normBound    maximum norm for valid signatures
     * @param keyNormBound maximum norm for the ploynomials <code>F</code> and <code>G</code>
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public NTRUSigningParameters(int N, int q, int d1, int d2, int d3, int B, double beta, double normBound, double keyNormBound, Digest hashAlg)
    {
        this.N = N;
        this.q = q;
        this.d1 = d1;
        this.d2 = d2;
        this.d3 = d3;
        this.B = B;
        this.beta = beta;
        this.normBound = normBound;
        this.hashAlg = hashAlg;
        init();
    }

    private void init()
    {
        betaSq = beta * beta;
        normBoundSq = normBound * normBound;
    }

    /**
     * Reads a parameter set from an input stream.
     *
     * @param is an input stream
     * @throws IOException
     */
    public NTRUSigningParameters(InputStream is)
        throws IOException
    {
        DataInputStream dis = new DataInputStream(is);
        N = dis.readInt();
        q = dis.readInt();
        d = dis.readInt();
        d1 = dis.readInt();
        d2 = dis.readInt();
        d3 = dis.readInt();
        B = dis.readInt();
        beta = dis.readDouble();
        normBound = dis.readDouble();
        signFailTolerance = dis.readInt();
        bitsF = dis.readInt();
        String alg = dis.readUTF();
        if ("SHA-512".equals(alg))
        {
            hashAlg = new SHA512Digest();
        }
        else if ("SHA-256".equals(alg))
        {
            hashAlg = new SHA256Digest();
        }
        init();
    }

    /**
     * Writes the parameter set to an output stream
     *
     * @param os an output stream
     * @throws IOException
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
        dos.writeDouble(beta);
        dos.writeDouble(normBound);
        dos.writeInt(signFailTolerance);
        dos.writeInt(bitsF);
        dos.writeUTF(hashAlg.getAlgorithmName());
    }

    public NTRUSigningParameters clone()
    {
        return new NTRUSigningParameters(N, q, d, B, beta, normBound, hashAlg);
    }

    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + B;
        result = prime * result + N;
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
        temp = Double.doubleToLongBits(normBound);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(normBoundSq);
        result = prime * result + (int)(temp ^ (temp >>> 32));
        result = prime * result + q;
        result = prime * result + signFailTolerance;
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
        if (!(obj instanceof NTRUSigningParameters))
        {
            return false;
        }
        NTRUSigningParameters other = (NTRUSigningParameters)obj;
        if (B != other.B)
        {
            return false;
        }
        if (N != other.N)
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
        if (Double.doubleToLongBits(normBound) != Double.doubleToLongBits(other.normBound))
        {
            return false;
        }
        if (Double.doubleToLongBits(normBoundSq) != Double.doubleToLongBits(other.normBoundSq))
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

        return true;
    }

    public String toString()
    {
        DecimalFormat format = new DecimalFormat("0.00");

        StringBuilder output = new StringBuilder("SignatureParameters(N=" + N + " q=" + q);

        output.append(" B=" + B + " beta=" + format.format(beta) +
            " normBound=" + format.format(normBound) +
            " hashAlg=" + hashAlg + ")");
        return output.toString();
    }
}
