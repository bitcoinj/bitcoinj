package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
import org.bouncycastle.pqc.math.ntru.util.Util;

/**
 * Generates key pairs.<br>
 * The parameter p is hardcoded to 3.
 */
public class NTRUEncryptionKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private NTRUEncryptionKeyGenerationParameters params;

    /**
     * Constructs a new instance with a set of encryption parameters.
     *
     * @param param encryption parameters
     */
    public void init(KeyGenerationParameters param)
    {
        this.params = (NTRUEncryptionKeyGenerationParameters)param;
    }

    /**
     * Generates a new encryption key pair.
     *
     * @return a key pair
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int N = params.N;
        int q = params.q;
        int df = params.df;
        int df1 = params.df1;
        int df2 = params.df2;
        int df3 = params.df3;
        int dg = params.dg;
        boolean fastFp = params.fastFp;
        boolean sparse = params.sparse;

        Polynomial t;
        IntegerPolynomial fq;
        IntegerPolynomial fp = null;

        // choose a random f that is invertible mod 3 and q
        while (true)
        {
            IntegerPolynomial f;

            // choose random t, calculate f and fp
            if (fastFp)
            {
                // if fastFp=true, f is always invertible mod 3
                t = params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE ? Util.generateRandomTernary(N, df, df, sparse, params.getRandom()) : ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3, params.getRandom());
                f = t.toIntegerPolynomial();
                f.mult(3);
                f.coeffs[0] += 1;
            }
            else
            {
                t = params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE ? Util.generateRandomTernary(N, df, df - 1, sparse, params.getRandom()) : ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3 - 1, params.getRandom());
                f = t.toIntegerPolynomial();
                fp = f.invertF3();
                if (fp == null)
                {
                    continue;
                }
            }

            fq = f.invertFq(q);
            if (fq == null)
            {
                continue;
            }
            break;
        }

        // if fastFp=true, fp=1
        if (fastFp)
        {
            fp = new IntegerPolynomial(N);
            fp.coeffs[0] = 1;
        }

        // choose a random g that is invertible mod q
        DenseTernaryPolynomial g;
        while (true)
        {
            g = DenseTernaryPolynomial.generateRandom(N, dg, dg - 1, params.getRandom());
            if (g.invertFq(q) != null)
            {
                break;
            }
        }

        IntegerPolynomial h = g.mult(fq, q);
        h.mult3(q);
        h.ensurePositive(q);
        g.clear();
        fq.clear();

        NTRUEncryptionPrivateKeyParameters priv = new NTRUEncryptionPrivateKeyParameters(h, t, fp, params.getEncryptionParameters());
        NTRUEncryptionPublicKeyParameters pub = new NTRUEncryptionPublicKeyParameters(h, params.getEncryptionParameters());
        return new AsymmetricCipherKeyPair(pub, priv);
    }
}