package org.bouncycastle.pqc.math.ntru.polynomial;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

/**
 * A polynomial of the form <code>f1*f2+f3</code>, where
 * <code>f1,f2,f3</code> are very sparsely populated ternary polynomials.
 */
public class ProductFormPolynomial
    implements Polynomial
{
    private SparseTernaryPolynomial f1, f2, f3;

    public ProductFormPolynomial(SparseTernaryPolynomial f1, SparseTernaryPolynomial f2, SparseTernaryPolynomial f3)
    {
        this.f1 = f1;
        this.f2 = f2;
        this.f3 = f3;
    }

    public static ProductFormPolynomial generateRandom(int N, int df1, int df2, int df3Ones, int df3NegOnes, SecureRandom random)
    {
        SparseTernaryPolynomial f1 = SparseTernaryPolynomial.generateRandom(N, df1, df1, random);
        SparseTernaryPolynomial f2 = SparseTernaryPolynomial.generateRandom(N, df2, df2, random);
        SparseTernaryPolynomial f3 = SparseTernaryPolynomial.generateRandom(N, df3Ones, df3NegOnes, random);
        return new ProductFormPolynomial(f1, f2, f3);
    }

    public static ProductFormPolynomial fromBinary(byte[] data, int N, int df1, int df2, int df3Ones, int df3NegOnes)
        throws IOException
    {
        return fromBinary(new ByteArrayInputStream(data), N, df1, df2, df3Ones, df3NegOnes);
    }

    public static ProductFormPolynomial fromBinary(InputStream is, int N, int df1, int df2, int df3Ones, int df3NegOnes)
        throws IOException
    {
        SparseTernaryPolynomial f1;

        f1 = SparseTernaryPolynomial.fromBinary(is, N, df1, df1);
        SparseTernaryPolynomial f2 = SparseTernaryPolynomial.fromBinary(is, N, df2, df2);
        SparseTernaryPolynomial f3 = SparseTernaryPolynomial.fromBinary(is, N, df3Ones, df3NegOnes);
        return new ProductFormPolynomial(f1, f2, f3);
    }

    public byte[] toBinary()
    {
        byte[] f1Bin = f1.toBinary();
        byte[] f2Bin = f2.toBinary();
        byte[] f3Bin = f3.toBinary();

        byte[] all = Arrays.copyOf(f1Bin, f1Bin.length + f2Bin.length + f3Bin.length);
        System.arraycopy(f2Bin, 0, all, f1Bin.length, f2Bin.length);
        System.arraycopy(f3Bin, 0, all, f1Bin.length + f2Bin.length, f3Bin.length);
        return all;
    }

    public IntegerPolynomial mult(IntegerPolynomial b)
    {
        IntegerPolynomial c = f1.mult(b);
        c = f2.mult(c);
        c.add(f3.mult(b));
        return c;
    }

    public BigIntPolynomial mult(BigIntPolynomial b)
    {
        BigIntPolynomial c = f1.mult(b);
        c = f2.mult(c);
        c.add(f3.mult(b));
        return c;
    }

    public IntegerPolynomial toIntegerPolynomial()
    {
        IntegerPolynomial i = f1.mult(f2.toIntegerPolynomial());
        i.add(f3.toIntegerPolynomial());
        return i;
    }

    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus)
    {
        IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((f1 == null) ? 0 : f1.hashCode());
        result = prime * result + ((f2 == null) ? 0 : f2.hashCode());
        result = prime * result + ((f3 == null) ? 0 : f3.hashCode());
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
        if (getClass() != obj.getClass())
        {
            return false;
        }
        ProductFormPolynomial other = (ProductFormPolynomial)obj;
        if (f1 == null)
        {
            if (other.f1 != null)
            {
                return false;
            }
        }
        else if (!f1.equals(other.f1))
        {
            return false;
        }
        if (f2 == null)
        {
            if (other.f2 != null)
            {
                return false;
            }
        }
        else if (!f2.equals(other.f2))
        {
            return false;
        }
        if (f3 == null)
        {
            if (other.f3 != null)
            {
                return false;
            }
        }
        else if (!f3.equals(other.f3))
        {
            return false;
        }
        return true;
    }
}
