package org.bouncycastle.pqc.math.linearalgebra;


import java.util.Random;
import java.util.Vector;


/**
 * This class implements the abstract class <tt>GF2nField</tt> for ONB
 * representation. It computes the fieldpolynomial, multiplication matrix and
 * one of its roots mONBRoot, (see for example <a
 * href=http://www2.certicom.com/ecc/intro.htm>Certicoms Whitepapers</a>).
 * GF2nField is used by GF2nONBElement which implements the elements of this
 * field.
 *
 * @see GF2nField
 * @see GF2nONBElement
 */
public class GF2nONBField
    extends GF2nField
{

    // ///////////////////////////////////////////////////////////////////
    // Hashtable for irreducible normal polynomials //
    // ///////////////////////////////////////////////////////////////////

    // i*5 + 0 i*5 + 1 i*5 + 2 i*5 + 3 i*5 + 4
    /*
     * private static int[][] mNB = {{0, 0, 0}, {0, 0, 0}, {1, 0, 0}, {1, 0, 0},
     * {1, 0, 0}, // i = 0 {2, 0, 0}, {1, 0, 0}, {1, 0, 0}, {4, 3, 1}, {1, 0,
     * 0}, // i = 1 {3, 0, 0}, {2, 0, 0}, {3, 0, 0}, {4, 3, 1}, {5, 0, 0}, // i =
     * 2 {1, 0, 0}, {5, 3, 1}, {3, 0, 0}, {3, 0, 0}, {5, 2, 1}, // i = 3 {3, 0,
     * 0}, {2, 0, 0}, {1, 0, 0}, {5, 0, 0}, {4, 3, 1}, // i = 4 {3, 0, 0}, {4,
     * 3, 1}, {5, 2, 1}, {1, 0, 0}, {2, 0, 0}, // i = 5 {1, 0, 0}, {3, 0, 0},
     * {7, 3, 2}, {10, 0, 0}, {7, 0, 0}, // i = 6 {2, 0, 0}, {9, 0, 0}, {6, 4,
     * 1}, {6, 5, 1}, {4, 0, 0}, // i = 7 {5, 4, 3}, {3, 0, 0}, {7, 0, 0}, {6,
     * 4, 3}, {5, 0, 0}, // i = 8 {4, 3, 1}, {1, 0, 0}, {5, 0, 0}, {5, 3, 2},
     * {9, 0, 0}, // i = 9 {4, 3, 2}, {6, 3, 1}, {3, 0, 0}, {6, 2, 1}, {9, 0,
     * 0}, // i = 10 {7, 0, 0}, {7, 4, 2}, {4, 0, 0}, {19, 0, 0}, {7, 4, 2}, //
     * i = 11 {1, 0, 0}, {5, 2, 1}, {29, 0, 0}, {1, 0, 0}, {4, 3, 1}, // i = 12
     * {18, 0, 0}, {3, 0, 0}, {5, 2, 1}, {9, 0, 0}, {6, 5, 2}, // i = 13 {5, 3,
     * 1}, {6, 0, 0}, {10, 9, 3}, {25, 0, 0}, {35, 0, 0}, // i = 14 {6, 3, 1},
     * {21, 0, 0}, {6, 5, 2}, {6, 5, 3}, {9, 0, 0}, // i = 15 {9, 4, 2}, {4, 0,
     * 0}, {8, 3, 1}, {7, 4, 2}, {5, 0, 0}, // i = 16 {8, 2, 1}, {21, 0, 0},
     * {13, 0, 0}, {7, 6, 2}, {38, 0, 0}, // i = 17 {27, 0, 0}, {8, 5, 1}, {21,
     * 0, 0}, {2, 0, 0}, {21, 0, 0}, // i = 18 {11, 0, 0}, {10, 9, 6}, {6, 0,
     * 0}, {11, 0, 0}, {6, 3, 1}, // i = 19 {15, 0, 0}, {7, 6, 1}, {29, 0, 0},
     * {9, 0, 0}, {4, 3, 1}, // i = 20 {4, 0, 0}, {15, 0, 0}, {9, 7, 4}, {17, 0,
     * 0}, {5, 4, 2}, // i = 21 {33, 0, 0}, {10, 0, 0}, {5, 4, 3}, {9, 0, 0},
     * {5, 3, 2}, // i = 22 {8, 7, 5}, {4, 2, 1}, {5, 2, 1}, {33, 0, 0}, {8, 0,
     * 0}, // i = 23 {4, 3, 1}, {18, 0, 0}, {6, 2, 1}, {2, 0, 0}, {19, 0, 0}, //
     * i = 24 {7, 6, 5}, {21, 0, 0}, {1, 0, 0}, {7, 2, 1}, {5, 0, 0}, // i = 25
     * {3, 0, 0}, {8, 3, 2}, {17, 0, 0}, {9, 8, 2}, {57, 0, 0}, // i = 26 {11,
     * 0, 0}, {5, 3, 2}, {21, 0, 0}, {8, 7, 1}, {8, 5, 3}, // i = 27 {15, 0, 0},
     * {10, 4, 1}, {21, 0, 0}, {5, 3, 2}, {7, 4, 2}, // i = 28 {52, 0, 0}, {71,
     * 0, 0}, {14, 0, 0}, {27, 0, 0}, {10, 9, 7}, // i = 29 {53, 0, 0}, {3, 0,
     * 0}, {6, 3, 2}, {1, 0, 0}, {15, 0, 0}, // i = 30 {62, 0, 0}, {9, 0, 0},
     * {6, 5, 2}, {8, 6, 5}, {31, 0, 0}, // i = 31 {5, 3, 2}, {18, 0, 0 }, {27,
     * 0, 0}, {7, 6, 3}, {10, 8, 7}, // i = 32 {9, 8, 3}, {37, 0, 0}, {6, 0, 0},
     * {15, 3, 2}, {34, 0, 0}, // i = 33 {11, 0, 0}, {6, 5, 2}, {1, 0, 0}, {8,
     * 5, 2}, {13, 0, 0}, // i = 34 {6, 0, 0}, {11, 3, 2}, {8, 0, 0}, {31, 0,
     * 0}, {4, 2, 1}, // i = 35 {3, 0, 0}, {7, 6, 1}, {81, 0, 0}, {56, 0, 0},
     * {9, 8, 7}, // i = 36 {24, 0, 0}, {11, 0, 0}, {7, 6, 5}, {6, 5, 2}, {6, 5,
     * 2}, // i = 37 {8, 7, 6}, {9, 0, 0}, {7, 2, 1}, {15, 0, 0}, {87, 0, 0}, //
     * i = 38 {8, 3, 2}, {3, 0, 0}, {9, 4, 2}, {9, 0, 0}, {34, 0, 0}, // i = 39
     * {5, 3, 2}, {14, 0, 0}, {55, 0, 0}, {8, 7, 1}, {27, 0, 0}, // i = 40 {9,
     * 5, 2}, {10, 9, 5}, {43, 0, 0}, {8, 6, 2}, {6, 0, 0}, // i = 41 {7, 0, 0},
     * {11, 10, 8}, {105, 0, 0}, {6, 5, 2}, {73, 0, 0}}; // i = 42
     */
    // /////////////////////////////////////////////////////////////////////
    // member variables
    // /////////////////////////////////////////////////////////////////////
    private static final int MAXLONG = 64;

    /**
     * holds the length of the array-representation of degree mDegree.
     */
    private int mLength;

    /**
     * holds the number of relevant bits in mONBPol[mLength-1].
     */
    private int mBit;

    /**
     * holds the type of mONB
     */
    private int mType;

    /**
     * holds the multiplication matrix
     */
    int[][] mMult;

    // /////////////////////////////////////////////////////////////////////
    // constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * constructs an instance of the finite field with 2<sup>deg</sup>
     * elements and characteristic 2.
     *
     * @param deg -
     *            the extention degree of this field
     * @throws NoSuchBasisException if an ONB-implementation other than type 1 or type 2 is
     * requested.
     */
    public GF2nONBField(int deg)
        throws RuntimeException
    {
        if (deg < 3)
        {
            throw new IllegalArgumentException("k must be at least 3");
        }

        mDegree = deg;
        mLength = mDegree / MAXLONG;
        mBit = mDegree & (MAXLONG - 1);
        if (mBit == 0)
        {
            mBit = MAXLONG;
        }
        else
        {
            mLength++;
        }

        computeType();

        // only ONB-implementations for type 1 and type 2
        //
        if (mType < 3)
        {
            mMult = new int[mDegree][2];
            for (int i = 0; i < mDegree; i++)
            {
                mMult[i][0] = -1;
                mMult[i][1] = -1;
            }
            computeMultMatrix();
        }
        else
        {
            throw new RuntimeException("\nThe type of this field is "
                + mType);
        }
        computeFieldPolynomial();
        fields = new Vector();
        matrices = new Vector();
    }

    // /////////////////////////////////////////////////////////////////////
    // access
    // /////////////////////////////////////////////////////////////////////

    int getONBLength()
    {
        return mLength;
    }

    int getONBBit()
    {
        return mBit;
    }

    // /////////////////////////////////////////////////////////////////////
    // arithmetic
    // /////////////////////////////////////////////////////////////////////

    /**
     * Computes a random root of the given polynomial.
     *
     * @param polynomial a polynomial
     * @return a random root of the polynomial
     * @see "P1363 A.5.6, p103f"
     */
    protected GF2nElement getRandomRoot(GF2Polynomial polynomial)
    {
        // We are in B1!!!
        GF2nPolynomial c;
        GF2nPolynomial ut;
        GF2nElement u;
        GF2nPolynomial h;
        int hDegree;
        // 1. Set g(t) <- f(t)
        GF2nPolynomial g = new GF2nPolynomial(polynomial, this);
        int gDegree = g.getDegree();
        int i;

        // 2. while deg(g) > 1
        while (gDegree > 1)
        {
            do
            {
                // 2.1 choose random u (element of) GF(2^m)
                u = new GF2nONBElement(this, new Random());
                ut = new GF2nPolynomial(2, GF2nONBElement.ZERO(this));
                // 2.2 Set c(t) <- ut
                ut.set(1, u);
                c = new GF2nPolynomial(ut);
                // 2.3 For i from 1 to m-1 do
                for (i = 1; i <= mDegree - 1; i++)
                {
                    // 2.3.1 c(t) <- (c(t)^2 + ut) mod g(t)
                    c = c.multiplyAndReduce(c, g);
                    c = c.add(ut);
                }
                // 2.4 set h(t) <- GCD(c(t), g(t))
                h = c.gcd(g);
                // 2.5 if h(t) is constant or deg(g) = deg(h) then go to
                // step 2.1
                hDegree = h.getDegree();
                gDegree = g.getDegree();
            }
            while ((hDegree == 0) || (hDegree == gDegree));
            // 2.6 If 2deg(h) > deg(g) then set g(t) <- g(t)/h(t) ...
            if ((hDegree << 1) > gDegree)
            {
                g = g.quotient(h);
            }
            else
            {
                // ... else g(t) <- h(t)
                g = new GF2nPolynomial(h);
            }
            gDegree = g.getDegree();
        }
        // 3. Output g(0)
        return g.at(0);

    }

    /**
     * Computes the change-of-basis matrix for basis conversion according to
     * 1363. The result is stored in the lists fields and matrices.
     *
     * @param B1 the GF2nField to convert to
     * @see "P1363 A.7.3, p111ff"
     */
    protected void computeCOBMatrix(GF2nField B1)
    {
        // we are in B0 here!
        if (mDegree != B1.mDegree)
        {
            throw new IllegalArgumentException(
                "GF2nField.computeCOBMatrix: B1 has a "
                    + "different degree and thus cannot be coverted to!");
        }
        int i, j;
        GF2nElement[] gamma;
        GF2nElement u;
        GF2Polynomial[] COBMatrix = new GF2Polynomial[mDegree];
        for (i = 0; i < mDegree; i++)
        {
            COBMatrix[i] = new GF2Polynomial(mDegree);
        }

        // find Random Root
        do
        {
            // u is in representation according to B1
            u = B1.getRandomRoot(fieldPolynomial);
        }
        while (u.isZero());

        gamma = new GF2nPolynomialElement[mDegree];
        // build gamma matrix by squaring
        gamma[0] = (GF2nElement)u.clone();
        for (i = 1; i < mDegree; i++)
        {
            gamma[i] = gamma[i - 1].square();
        }
        // convert horizontal gamma matrix by vertical Bitstrings
        for (i = 0; i < mDegree; i++)
        {
            for (j = 0; j < mDegree; j++)
            {
                if (gamma[i].testBit(j))
                {
                    COBMatrix[mDegree - j - 1].setBit(mDegree - i - 1);
                }
            }
        }

        fields.addElement(B1);
        matrices.addElement(COBMatrix);
        B1.fields.addElement(this);
        B1.matrices.addElement(invertMatrix(COBMatrix));
    }

    /**
     * Computes the field polynomial for a ONB according to IEEE 1363 A.7.2
     * (p110f).
     *
     * @see "P1363 A.7.2, p110f"
     */
    protected void computeFieldPolynomial()
    {
        if (mType == 1)
        {
            fieldPolynomial = new GF2Polynomial(mDegree + 1, "ALL");
        }
        else if (mType == 2)
        {
            // 1. q = 1
            GF2Polynomial q = new GF2Polynomial(mDegree + 1, "ONE");
            // 2. p = t+1
            GF2Polynomial p = new GF2Polynomial(mDegree + 1, "X");
            p.addToThis(q);
            GF2Polynomial r;
            int i;
            // 3. for i = 1 to (m-1) do
            for (i = 1; i < mDegree; i++)
            {
                // r <- q
                r = q;
                // q <- p
                q = p;
                // p = tq+r
                p = q.shiftLeft();
                p.addToThis(r);
            }
            fieldPolynomial = p;
        }
    }

    /**
     * Compute the inverse of a matrix <tt>a</tt>.
     *
     * @param a the matrix
     * @return <tt>a<sup>-1</sup></tt>
     */
    int[][] invMatrix(int[][] a)
    {

        int[][] A = new int[mDegree][mDegree];
        A = a;
        int[][] inv = new int[mDegree][mDegree];

        for (int i = 0; i < mDegree; i++)
        {
            inv[i][i] = 1;
        }

        for (int i = 0; i < mDegree; i++)
        {
            for (int j = i; j < mDegree; j++)
            {
                A[mDegree - 1 - i][j] = A[i][i];
            }
        }
        return null;
    }

    private void computeType()
        throws RuntimeException
    {
        if ((mDegree & 7) == 0)
        {
            throw new RuntimeException(
                "The extension degree is divisible by 8!");
        }
        // checking for the type
        int s = 0;
        int k = 0;
        mType = 1;
        for (int d = 0; d != 1; mType++)
        {
            s = mType * mDegree + 1;
            if (IntegerFunctions.isPrime(s))
            {
                k = IntegerFunctions.order(2, s);
                d = IntegerFunctions.gcd(mType * mDegree / k, mDegree);
            }
        }
        mType--;
        if (mType == 1)
        {
            s = (mDegree << 1) + 1;
            if (IntegerFunctions.isPrime(s))
            {
                k = IntegerFunctions.order(2, s);
                int d = IntegerFunctions.gcd((mDegree << 1) / k, mDegree);
                if (d == 1)
                {
                    mType++;
                }
            }
        }
    }

    private void computeMultMatrix()
    {

        if ((mType & 7) != 0)
        {
            int p = mType * mDegree + 1;

            // compute sequence F[1] ... F[p-1] via A.3.7. of 1363.
            // F[0] will not be filled!
            //
            int[] F = new int[p];

            int u;
            if (mType == 1)
            {
                u = 1;
            }
            else if (mType == 2)
            {
                u = p - 1;
            }
            else
            {
                u = elementOfOrder(mType, p);
            }

            int w = 1;
            int n;
            for (int j = 0; j < mType; j++)
            {
                n = w;

                for (int i = 0; i < mDegree; i++)
                {
                    F[n] = i;
                    n = (n << 1) % p;
                    if (n < 0)
                    {
                        n += p;
                    }
                }
                w = u * w % p;
                if (w < 0)
                {
                    w += p;
                }
            }

            // building the matrix (mDegree * 2)
            //
            if (mType == 1)
            {
                for (int k = 1; k < p - 1; k++)
                {
                    if (mMult[F[k + 1]][0] == -1)
                    {
                        mMult[F[k + 1]][0] = F[p - k];
                    }
                    else
                    {
                        mMult[F[k + 1]][1] = F[p - k];
                    }
                }

                int m_2 = mDegree >> 1;
                for (int k = 1; k <= m_2; k++)
                {

                    if (mMult[k - 1][0] == -1)
                    {
                        mMult[k - 1][0] = m_2 + k - 1;
                    }
                    else
                    {
                        mMult[k - 1][1] = m_2 + k - 1;
                    }

                    if (mMult[m_2 + k - 1][0] == -1)
                    {
                        mMult[m_2 + k - 1][0] = k - 1;
                    }
                    else
                    {
                        mMult[m_2 + k - 1][1] = k - 1;
                    }
                }
            }
            else if (mType == 2)
            {
                for (int k = 1; k < p - 1; k++)
                {
                    if (mMult[F[k + 1]][0] == -1)
                    {
                        mMult[F[k + 1]][0] = F[p - k];
                    }
                    else
                    {
                        mMult[F[k + 1]][1] = F[p - k];
                    }
                }
            }
            else
            {
                throw new RuntimeException("only type 1 or type 2 implemented");
            }
        }
        else
        {
            throw new RuntimeException("bisher nur fuer Gausssche Normalbasen"
                + " implementiert");
        }
    }

    private int elementOfOrder(int k, int p)
    {
        Random random = new Random();
        int m = 0;
        while (m == 0)
        {
            m = random.nextInt();
            m %= p - 1;
            if (m < 0)
            {
                m += p - 1;
            }
        }

        int l = IntegerFunctions.order(m, p);

        while (l % k != 0 || l == 0)
        {
            while (m == 0)
            {
                m = random.nextInt();
                m %= p - 1;
                if (m < 0)
                {
                    m += p - 1;
                }
            }
            l = IntegerFunctions.order(m, p);
        }
        int r = m;

        l = k / l;

        for (int i = 2; i <= l; i++)
        {
            r *= m;
        }

        return r;
    }

}
