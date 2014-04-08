package org.bouncycastle.pqc.math.linearalgebra;


import java.util.Random;
import java.util.Vector;


/**
 * This class implements the abstract class <tt>GF2nField</tt> for polynomial
 * representation. It computes the field polynomial and the squaring matrix.
 * GF2nField is used by GF2nPolynomialElement which implements the elements of
 * this field.
 *
 * @see GF2nField
 * @see GF2nPolynomialElement
 */
public class GF2nPolynomialField
    extends GF2nField
{

    /**
     * Matrix used for fast squaring
     */
    GF2Polynomial[] squaringMatrix;

    // field polynomial is a trinomial
    private boolean isTrinomial = false;

    // field polynomial is a pentanomial
    private boolean isPentanomial = false;

    // middle coefficient of the field polynomial in case it is a trinomial
    private int tc;

    // middle 3 coefficients of the field polynomial in case it is a pentanomial
    private int[] pc = new int[3];

    /**
     * constructs an instance of the finite field with 2<sup>deg</sup>
     * elements and characteristic 2.
     *
     * @param deg the extention degree of this field
     */
    public GF2nPolynomialField(int deg)
    {
        if (deg < 3)
        {
            throw new IllegalArgumentException("k must be at least 3");
        }
        mDegree = deg;
        computeFieldPolynomial();
        computeSquaringMatrix();
        fields = new Vector();
        matrices = new Vector();
    }

    /**
     * constructs an instance of the finite field with 2<sup>deg</sup>
     * elements and characteristic 2.
     *
     * @param deg  the degree of this field
     * @param file true if you want to read the field polynomial from the
     *             file false if you want to use a random fielpolynomial
     *             (this can take very long for huge degrees)
     */
    public GF2nPolynomialField(int deg, boolean file)
    {
        if (deg < 3)
        {
            throw new IllegalArgumentException("k must be at least 3");
        }
        mDegree = deg;
        if (file)
        {
            computeFieldPolynomial();
        }
        else
        {
            computeFieldPolynomial2();
        }
        computeSquaringMatrix();
        fields = new Vector();
        matrices = new Vector();
    }

    /**
     * Creates a new GF2nField of degree <i>i</i> and uses the given
     * <i>polynomial</i> as field polynomial. The <i>polynomial</i> is checked
     * whether it is irreducible. This can take some time if <i>i</i> is huge!
     *
     * @param deg        degree of the GF2nField
     * @param polynomial the field polynomial to use
     * @throws PolynomialIsNotIrreducibleException if the given polynomial is not irreducible in GF(2^<i>i</i>)
     */
    public GF2nPolynomialField(int deg, GF2Polynomial polynomial)
        throws RuntimeException
    {
        if (deg < 3)
        {
            throw new IllegalArgumentException("degree must be at least 3");
        }
        if (polynomial.getLength() != deg + 1)
        {
            throw new RuntimeException();
        }
        if (!polynomial.isIrreducible())
        {
            throw new RuntimeException();
        }
        mDegree = deg;
        // fieldPolynomial = new Bitstring(polynomial);
        fieldPolynomial = polynomial;
        computeSquaringMatrix();
        int k = 2; // check if the polynomial is a trinomial or pentanomial
        for (int j = 1; j < fieldPolynomial.getLength() - 1; j++)
        {
            if (fieldPolynomial.testBit(j))
            {
                k++;
                if (k == 3)
                {
                    tc = j;
                }
                if (k <= 5)
                {
                    pc[k - 3] = j;
                }
            }
        }
        if (k == 3)
        {
            isTrinomial = true;
        }
        if (k == 5)
        {
            isPentanomial = true;
        }
        fields = new Vector();
        matrices = new Vector();
    }

    /**
     * Returns true if the field polynomial is a trinomial. The coefficient can
     * be retrieved using getTc().
     *
     * @return true if the field polynomial is a trinomial
     */
    public boolean isTrinomial()
    {
        return isTrinomial;
    }

    /**
     * Returns true if the field polynomial is a pentanomial. The coefficients
     * can be retrieved using getPc().
     *
     * @return true if the field polynomial is a pentanomial
     */
    public boolean isPentanomial()
    {
        return isPentanomial;
    }

    /**
     * Returns the degree of the middle coefficient of the used field trinomial
     * (x^n + x^(getTc()) + 1).
     *
     * @return the middle coefficient of the used field trinomial
     * @throws GFException if the field polynomial is not a trinomial
     */
    public int getTc()
        throws RuntimeException
    {
        if (!isTrinomial)
        {
            throw new RuntimeException();
        }
        return tc;
    }

    /**
     * Returns the degree of the middle coefficients of the used field
     * pentanomial (x^n + x^(getPc()[2]) + x^(getPc()[1]) + x^(getPc()[0]) + 1).
     *
     * @return the middle coefficients of the used field pentanomial
     * @throws GFException if the field polynomial is not a pentanomial
     */
    public int[] getPc()
        throws RuntimeException
    {
        if (!isPentanomial)
        {
            throw new RuntimeException();
        }
        int[] result = new int[3];
        System.arraycopy(pc, 0, result, 0, 3);
        return result;
    }

    /**
     * Return row vector i of the squaring matrix.
     *
     * @param i the index of the row vector to return
     * @return a copy of squaringMatrix[i]
     * @see GF2nPolynomialElement#squareMatrix
     */
    public GF2Polynomial getSquaringVector(int i)
    {
        return new GF2Polynomial(squaringMatrix[i]);
    }

    /**
     * Compute a random root of the given GF2Polynomial.
     *
     * @param polynomial the polynomial
     * @return a random root of <tt>polynomial</tt>
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
                u = new GF2nPolynomialElement(this, new Random());
                ut = new GF2nPolynomial(2, GF2nPolynomialElement.ZERO(this));
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
                "GF2nPolynomialField.computeCOBMatrix: B1 has a different "
                    + "degree and thus cannot be coverted to!");
        }
        if (B1 instanceof GF2nONBField)
        {
            // speedup (calculation is done in PolynomialElements instead of
            // ONB)
            B1.computeCOBMatrix(this);
            return;
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

        // build gamma matrix by multiplying by u
        if (u instanceof GF2nONBElement)
        {
            gamma = new GF2nONBElement[mDegree];
            gamma[mDegree - 1] = GF2nONBElement.ONE((GF2nONBField)B1);
        }
        else
        {
            gamma = new GF2nPolynomialElement[mDegree];
            gamma[mDegree - 1] = GF2nPolynomialElement
                .ONE((GF2nPolynomialField)B1);
        }
        gamma[mDegree - 2] = u;
        for (i = mDegree - 3; i >= 0; i--)
        {
            gamma[i] = (GF2nElement)gamma[i + 1].multiply(u);
        }
        if (B1 instanceof GF2nONBField)
        {
            // convert horizontal gamma matrix by vertical Bitstrings
            for (i = 0; i < mDegree; i++)
            {
                for (j = 0; j < mDegree; j++)
                {
                    // TODO remember: ONB treats its Bits in reverse order !!!
                    if (gamma[i].testBit(mDegree - j - 1))
                    {
                        COBMatrix[mDegree - j - 1].setBit(mDegree - i - 1);
                    }
                }
            }
        }
        else
        {
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
        }

        // store field and matrix for further use
        fields.addElement(B1);
        matrices.addElement(COBMatrix);
        // store field and inverse matrix for further use in B1
        B1.fields.addElement(this);
        B1.matrices.addElement(invertMatrix(COBMatrix));
    }

    /**
     * Computes a new squaring matrix used for fast squaring.
     *
     * @see GF2nPolynomialElement#square
     */
    private void computeSquaringMatrix()
    {
        GF2Polynomial[] d = new GF2Polynomial[mDegree - 1];
        int i, j;
        squaringMatrix = new GF2Polynomial[mDegree];
        for (i = 0; i < squaringMatrix.length; i++)
        {
            squaringMatrix[i] = new GF2Polynomial(mDegree, "ZERO");
        }

        for (i = 0; i < mDegree - 1; i++)
        {
            d[i] = new GF2Polynomial(1, "ONE").shiftLeft(mDegree + i)
                .remainder(fieldPolynomial);
        }
        for (i = 1; i <= Math.abs(mDegree >> 1); i++)
        {
            for (j = 1; j <= mDegree; j++)
            {
                if (d[mDegree - (i << 1)].testBit(mDegree - j))
                {
                    squaringMatrix[j - 1].setBit(mDegree - i);
                }
            }
        }
        for (i = Math.abs(mDegree >> 1) + 1; i <= mDegree; i++)
        {
            squaringMatrix[(i << 1) - mDegree - 1].setBit(mDegree - i);
        }

    }

    /**
     * Computes the field polynomial. This can take a long time for big degrees.
     */
    protected void computeFieldPolynomial()
    {
        if (testTrinomials())
        {
            return;
        }
        if (testPentanomials())
        {
            return;
        }
        testRandom();
    }

    /**
     * Computes the field polynomial. This can take a long time for big degrees.
     */
    protected void computeFieldPolynomial2()
    {
        if (testTrinomials())
        {
            return;
        }
        if (testPentanomials())
        {
            return;
        }
        testRandom();
    }

    /**
     * Tests all trinomials of degree (n+1) until a irreducible is found and
     * stores the result in <i>field polynomial</i>. Returns false if no
     * irreducible trinomial exists in GF(2^n). This can take very long for huge
     * degrees.
     *
     * @return true if an irreducible trinomial is found
     */
    private boolean testTrinomials()
    {
        int i, l;
        boolean done = false;
        l = 0;

        fieldPolynomial = new GF2Polynomial(mDegree + 1);
        fieldPolynomial.setBit(0);
        fieldPolynomial.setBit(mDegree);
        for (i = 1; (i < mDegree) && !done; i++)
        {
            fieldPolynomial.setBit(i);
            done = fieldPolynomial.isIrreducible();
            l++;
            if (done)
            {
                isTrinomial = true;
                tc = i;
                return done;
            }
            fieldPolynomial.resetBit(i);
            done = fieldPolynomial.isIrreducible();
        }

        return done;
    }

    /**
     * Tests all pentanomials of degree (n+1) until a irreducible is found and
     * stores the result in <i>field polynomial</i>. Returns false if no
     * irreducible pentanomial exists in GF(2^n). This can take very long for
     * huge degrees.
     *
     * @return true if an irreducible pentanomial is found
     */
    private boolean testPentanomials()
    {
        int i, j, k, l;
        boolean done = false;
        l = 0;

        fieldPolynomial = new GF2Polynomial(mDegree + 1);
        fieldPolynomial.setBit(0);
        fieldPolynomial.setBit(mDegree);
        for (i = 1; (i <= (mDegree - 3)) && !done; i++)
        {
            fieldPolynomial.setBit(i);
            for (j = i + 1; (j <= (mDegree - 2)) && !done; j++)
            {
                fieldPolynomial.setBit(j);
                for (k = j + 1; (k <= (mDegree - 1)) && !done; k++)
                {
                    fieldPolynomial.setBit(k);
                    if (((mDegree & 1) != 0) | ((i & 1) != 0) | ((j & 1) != 0)
                        | ((k & 1) != 0))
                    {
                        done = fieldPolynomial.isIrreducible();
                        l++;
                        if (done)
                        {
                            isPentanomial = true;
                            pc[0] = i;
                            pc[1] = j;
                            pc[2] = k;
                            return done;
                        }
                    }
                    fieldPolynomial.resetBit(k);
                }
                fieldPolynomial.resetBit(j);
            }
            fieldPolynomial.resetBit(i);
        }

        return done;
    }

    /**
     * Tests random polynomials of degree (n+1) until an irreducible is found
     * and stores the result in <i>field polynomial</i>. This can take very
     * long for huge degrees.
     *
     * @return true
     */
    private boolean testRandom()
    {
        int l;
        boolean done = false;

        fieldPolynomial = new GF2Polynomial(mDegree + 1);
        l = 0;
        while (!done)
        {
            l++;
            fieldPolynomial.randomize();
            fieldPolynomial.setBit(mDegree);
            fieldPolynomial.setBit(0);
            if (fieldPolynomial.isIrreducible())
            {
                done = true;
                return done;
            }
        }

        return done;
    }

}
