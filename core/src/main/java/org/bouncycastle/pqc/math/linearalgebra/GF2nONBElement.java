package org.bouncycastle.pqc.math.linearalgebra;


import java.math.BigInteger;
import java.util.Random;

/**
 * This class implements an element of the finite field <i>GF(2<sup>n </sup>)</i>.
 * It is represented in an optimal normal basis representation and holds the
 * pointer <tt>mField</tt> to its corresponding field.
 *
 * @see GF2nField
 * @see GF2nElement
 */
public class GF2nONBElement
    extends GF2nElement
{

    // /////////////////////////////////////////////////////////////////////
    // member variables
    // /////////////////////////////////////////////////////////////////////

    private static final long[] mBitmask = new long[]{0x0000000000000001L,
        0x0000000000000002L, 0x0000000000000004L, 0x0000000000000008L,
        0x0000000000000010L, 0x0000000000000020L, 0x0000000000000040L,
        0x0000000000000080L, 0x0000000000000100L, 0x0000000000000200L,
        0x0000000000000400L, 0x0000000000000800L, 0x0000000000001000L,
        0x0000000000002000L, 0x0000000000004000L, 0x0000000000008000L,
        0x0000000000010000L, 0x0000000000020000L, 0x0000000000040000L,
        0x0000000000080000L, 0x0000000000100000L, 0x0000000000200000L,
        0x0000000000400000L, 0x0000000000800000L, 0x0000000001000000L,
        0x0000000002000000L, 0x0000000004000000L, 0x0000000008000000L,
        0x0000000010000000L, 0x0000000020000000L, 0x0000000040000000L,
        0x0000000080000000L, 0x0000000100000000L, 0x0000000200000000L,
        0x0000000400000000L, 0x0000000800000000L, 0x0000001000000000L,
        0x0000002000000000L, 0x0000004000000000L, 0x0000008000000000L,
        0x0000010000000000L, 0x0000020000000000L, 0x0000040000000000L,
        0x0000080000000000L, 0x0000100000000000L, 0x0000200000000000L,
        0x0000400000000000L, 0x0000800000000000L, 0x0001000000000000L,
        0x0002000000000000L, 0x0004000000000000L, 0x0008000000000000L,
        0x0010000000000000L, 0x0020000000000000L, 0x0040000000000000L,
        0x0080000000000000L, 0x0100000000000000L, 0x0200000000000000L,
        0x0400000000000000L, 0x0800000000000000L, 0x1000000000000000L,
        0x2000000000000000L, 0x4000000000000000L, 0x8000000000000000L};

    private static final long[] mMaxmask = new long[]{0x0000000000000001L,
        0x0000000000000003L, 0x0000000000000007L, 0x000000000000000FL,
        0x000000000000001FL, 0x000000000000003FL, 0x000000000000007FL,
        0x00000000000000FFL, 0x00000000000001FFL, 0x00000000000003FFL,
        0x00000000000007FFL, 0x0000000000000FFFL, 0x0000000000001FFFL,
        0x0000000000003FFFL, 0x0000000000007FFFL, 0x000000000000FFFFL,
        0x000000000001FFFFL, 0x000000000003FFFFL, 0x000000000007FFFFL,
        0x00000000000FFFFFL, 0x00000000001FFFFFL, 0x00000000003FFFFFL,
        0x00000000007FFFFFL, 0x0000000000FFFFFFL, 0x0000000001FFFFFFL,
        0x0000000003FFFFFFL, 0x0000000007FFFFFFL, 0x000000000FFFFFFFL,
        0x000000001FFFFFFFL, 0x000000003FFFFFFFL, 0x000000007FFFFFFFL,
        0x00000000FFFFFFFFL, 0x00000001FFFFFFFFL, 0x00000003FFFFFFFFL,
        0x00000007FFFFFFFFL, 0x0000000FFFFFFFFFL, 0x0000001FFFFFFFFFL,
        0x0000003FFFFFFFFFL, 0x0000007FFFFFFFFFL, 0x000000FFFFFFFFFFL,
        0x000001FFFFFFFFFFL, 0x000003FFFFFFFFFFL, 0x000007FFFFFFFFFFL,
        0x00000FFFFFFFFFFFL, 0x00001FFFFFFFFFFFL, 0x00003FFFFFFFFFFFL,
        0x00007FFFFFFFFFFFL, 0x0000FFFFFFFFFFFFL, 0x0001FFFFFFFFFFFFL,
        0x0003FFFFFFFFFFFFL, 0x0007FFFFFFFFFFFFL, 0x000FFFFFFFFFFFFFL,
        0x001FFFFFFFFFFFFFL, 0x003FFFFFFFFFFFFFL, 0x007FFFFFFFFFFFFFL,
        0x00FFFFFFFFFFFFFFL, 0x01FFFFFFFFFFFFFFL, 0x03FFFFFFFFFFFFFFL,
        0x07FFFFFFFFFFFFFFL, 0x0FFFFFFFFFFFFFFFL, 0x1FFFFFFFFFFFFFFFL,
        0x3FFFFFFFFFFFFFFFL, 0x7FFFFFFFFFFFFFFFL, 0xFFFFFFFFFFFFFFFFL};

    // mIBy64[j * 16 + i] = (j * 16 + i)/64
    // i =
    // 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
    //
    private static final int[] mIBY64 = new int[]{
        // j =
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 2
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 3
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 5
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 7
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 8
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 9
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 10
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 11
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 12
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 13
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 14
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 15
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 16
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 17
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 18
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 19
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 20
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 21
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 22
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 // 23
    };

    private static final int MAXLONG = 64;

    /**
     * holds the lenght of the polynomial with 64 bit sized fields.
     */
    private int mLength;

    /**
     * holds the value of mDeg % MAXLONG.
     */
    private int mBit;

    /**
     * holds this element in ONB representation.
     */
    private long[] mPol;

    // /////////////////////////////////////////////////////////////////////
    // constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * Construct a random element over the field <tt>gf2n</tt>, using the
     * specified source of randomness.
     *
     * @param gf2n the field
     * @param rand the source of randomness
     */
    public GF2nONBElement(GF2nONBField gf2n, Random rand)
    {
        mField = gf2n;
        mDegree = mField.getDegree();
        mLength = gf2n.getONBLength();
        mBit = gf2n.getONBBit();
        mPol = new long[mLength];
        if (mLength > 1)
        {
            for (int j = 0; j < mLength - 1; j++)
            {
                mPol[j] = rand.nextLong();
            }
            long last = rand.nextLong();
            mPol[mLength - 1] = last >>> (MAXLONG - mBit);
        }
        else
        {
            mPol[0] = rand.nextLong();
            mPol[0] = mPol[0] >>> (MAXLONG - mBit);
        }
    }

    /**
     * Construct a new GF2nONBElement from its encoding.
     *
     * @param gf2n the field
     * @param e    the encoded element
     */
    public GF2nONBElement(GF2nONBField gf2n, byte[] e)
    {
        mField = gf2n;
        mDegree = mField.getDegree();
        mLength = gf2n.getONBLength();
        mBit = gf2n.getONBBit();
        mPol = new long[mLength];
        assign(e);
    }

    /**
     * Construct the element of the field <tt>gf2n</tt> with the specified
     * value <tt>val</tt>.
     *
     * @param gf2n the field
     * @param val  the value represented by a BigInteger
     */
    public GF2nONBElement(GF2nONBField gf2n, BigInteger val)
    {
        mField = gf2n;
        mDegree = mField.getDegree();
        mLength = gf2n.getONBLength();
        mBit = gf2n.getONBBit();
        mPol = new long[mLength];
        assign(val);
    }

    /**
     * Construct the element of the field <tt>gf2n</tt> with the specified
     * value <tt>val</tt>.
     *
     * @param gf2n the field
     * @param val  the value in ONB representation
     */
    private GF2nONBElement(GF2nONBField gf2n, long[] val)
    {
        mField = gf2n;
        mDegree = mField.getDegree();
        mLength = gf2n.getONBLength();
        mBit = gf2n.getONBBit();
        mPol = val;
    }

    // /////////////////////////////////////////////////////////////////////
    // pseudo-constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * Copy constructor.
     *
     * @param gf2n the field
     */
    public GF2nONBElement(GF2nONBElement gf2n)
    {

        mField = gf2n.mField;
        mDegree = mField.getDegree();
        mLength = ((GF2nONBField)mField).getONBLength();
        mBit = ((GF2nONBField)mField).getONBBit();
        mPol = new long[mLength];
        assign(gf2n.getElement());
    }

    /**
     * Create a new GF2nONBElement by cloning this GF2nPolynomialElement.
     *
     * @return a copy of this element
     */
    public Object clone()
    {
        return new GF2nONBElement(this);
    }

    /**
     * Create the zero element.
     *
     * @param gf2n the finite field
     * @return the zero element in the given finite field
     */
    public static GF2nONBElement ZERO(GF2nONBField gf2n)
    {
        long[] polynomial = new long[gf2n.getONBLength()];
        return new GF2nONBElement(gf2n, polynomial);
    }

    /**
     * Create the one element.
     *
     * @param gf2n the finite field
     * @return the one element in the given finite field
     */
    public static GF2nONBElement ONE(GF2nONBField gf2n)
    {
        int mLength = gf2n.getONBLength();
        long[] polynomial = new long[mLength];

        // fill mDegree coefficients with one's
        for (int i = 0; i < mLength - 1; i++)
        {
            polynomial[i] = 0xffffffffffffffffL;
        }
        polynomial[mLength - 1] = mMaxmask[gf2n.getONBBit() - 1];

        return new GF2nONBElement(gf2n, polynomial);
    }

    // /////////////////////////////////////////////////////////////////////
    // assignments
    // /////////////////////////////////////////////////////////////////////

    /**
     * assigns to this element the zero element
     */
    void assignZero()
    {
        mPol = new long[mLength];
    }

    /**
     * assigns to this element the one element
     */
    void assignOne()
    {
        // fill mDegree coefficients with one's
        for (int i = 0; i < mLength - 1; i++)
        {
            mPol[i] = 0xffffffffffffffffL;
        }
        mPol[mLength - 1] = mMaxmask[mBit - 1];
    }

    /**
     * assigns to this element the value <tt>val</tt>.
     *
     * @param val the value represented by a BigInteger
     */
    private void assign(BigInteger val)
    {
        assign(val.toByteArray());
    }

    /**
     * assigns to this element the value <tt>val</tt>.
     *
     * @param val the value in ONB representation
     */
    private void assign(long[] val)
    {
        System.arraycopy(val, 0, mPol, 0, mLength);
    }

    /**
     * assigns to this element the value <tt>val</tt>. First: inverting the
     * order of val into reversed[]. That means: reversed[0] = val[length - 1],
     * ..., reversed[reversed.length - 1] = val[0]. Second: mPol[0] = sum{i = 0,
     * ... 7} (val[i]<<(i*8)) .... mPol[1] = sum{i = 8, ... 15} (val[i]<<(i*8))
     *
     * @param val the value in ONB representation
     */
    private void assign(byte[] val)
    {
        int j;
        mPol = new long[mLength];
        for (j = 0; j < val.length; j++)
        {
            mPol[j >>> 3] |= (val[val.length - 1 - j] & 0x00000000000000ffL) << ((j & 0x07) << 3);
        }
    }

    // /////////////////////////////////////////////////////////////////
    // comparison
    // /////////////////////////////////////////////////////////////////

    /**
     * Checks whether this element is zero.
     *
     * @return <tt>true</tt> if <tt>this</tt> is the zero element
     */
    public boolean isZero()
    {

        boolean result = true;

        for (int i = 0; i < mLength && result; i++)
        {
            result = result && ((mPol[i] & 0xFFFFFFFFFFFFFFFFL) == 0);
        }

        return result;
    }

    /**
     * Checks whether this element is one.
     *
     * @return <tt>true</tt> if <tt>this</tt> is the one element
     */
    public boolean isOne()
    {

        boolean result = true;

        for (int i = 0; i < mLength - 1 && result; i++)
        {
            result = result
                && ((mPol[i] & 0xFFFFFFFFFFFFFFFFL) == 0xFFFFFFFFFFFFFFFFL);
        }

        if (result)
        {
            result = result
                && ((mPol[mLength - 1] & mMaxmask[mBit - 1]) == mMaxmask[mBit - 1]);
        }

        return result;
    }

    /**
     * Compare this element with another object.
     *
     * @param other the other object
     * @return <tt>true</tt> if the two objects are equal, <tt>false</tt>
     *         otherwise
     */
    public boolean equals(Object other)
    {
        if (other == null || !(other instanceof GF2nONBElement))
        {
            return false;
        }

        GF2nONBElement otherElem = (GF2nONBElement)other;

        for (int i = 0; i < mLength; i++)
        {
            if (mPol[i] != otherElem.mPol[i])
            {
                return false;
            }
        }

        return true;
    }

    /**
     * @return the hash code of this element
     */
    public int hashCode()
    {
        return mPol.hashCode();
    }

    // /////////////////////////////////////////////////////////////////////
    // access
    // /////////////////////////////////////////////////////////////////////

    /**
     * Returns whether the highest bit of the bit representation is set
     *
     * @return true, if the highest bit of mPol is set, false, otherwise
     */
    public boolean testRightmostBit()
    {
        // due to the reverse bit order (compared to 1363) this method returns
        // the value of the leftmost bit
        return (mPol[mLength - 1] & mBitmask[mBit - 1]) != 0L;
    }

    /**
     * Checks whether the indexed bit of the bit representation is set. Warning:
     * GF2nONBElement currently stores its bits in reverse order (compared to
     * 1363) !!!
     *
     * @param index the index of the bit to test
     * @return <tt>true</tt> if the indexed bit of mPol is set, <tt>false</tt>
     *         otherwise.
     */
    boolean testBit(int index)
    {
        if (index < 0 || index > mDegree)
        {
            return false;
        }
        long test = mPol[index >>> 6] & mBitmask[index & 0x3f];
        return test != 0x0L;
    }

    /**
     * @return this element in its ONB representation
     */
    private long[] getElement()
    {

        long[] result = new long[mPol.length];
        System.arraycopy(mPol, 0, result, 0, mPol.length);

        return result;
    }

    /**
     * Returns the ONB representation of this element. The Bit-Order is
     * exchanged (according to 1363)!
     *
     * @return this element in its representation and reverse bit-order
     */
    private long[] getElementReverseOrder()
    {
        long[] result = new long[mPol.length];
        for (int i = 0; i < mDegree; i++)
        {
            if (testBit(mDegree - i - 1))
            {
                result[i >>> 6] |= mBitmask[i & 0x3f];
            }
        }
        return result;
    }

    /**
     * Reverses the bit-order in this element(according to 1363). This is a
     * hack!
     */
    void reverseOrder()
    {
        mPol = getElementReverseOrder();
    }

    // /////////////////////////////////////////////////////////////////////
    // arithmetic
    // /////////////////////////////////////////////////////////////////////

    /**
     * Compute the sum of this element and <tt>addend</tt>.
     *
     * @param addend the addend
     * @return <tt>this + other</tt> (newly created)
     * @throws DifferentFieldsException if the elements are of different fields.
     */
    public GFElement add(GFElement addend)
        throws RuntimeException
    {
        GF2nONBElement result = new GF2nONBElement(this);
        result.addToThis(addend);
        return result;
    }

    /**
     * Compute <tt>this + addend</tt> (overwrite <tt>this</tt>).
     *
     * @param addend the addend
     * @throws DifferentFieldsException if the elements are of different fields.
     */
    public void addToThis(GFElement addend)
        throws RuntimeException
    {
        if (!(addend instanceof GF2nONBElement))
        {
            throw new RuntimeException();
        }
        if (!mField.equals(((GF2nONBElement)addend).mField))
        {
            throw new RuntimeException();
        }

        for (int i = 0; i < mLength; i++)
        {
            mPol[i] ^= ((GF2nONBElement)addend).mPol[i];
        }
    }

    /**
     * returns <tt>this</tt> element + 1.
     *
     * @return <tt>this</tt> + 1
     */
    public GF2nElement increase()
    {
        GF2nONBElement result = new GF2nONBElement(this);
        result.increaseThis();
        return result;
    }

    /**
     * increases <tt>this</tt> element.
     */
    public void increaseThis()
    {
        addToThis(ONE((GF2nONBField)mField));
    }

    /**
     * Compute the product of this element and <tt>factor</tt>.
     *
     * @param factor the factor
     * @return <tt>this * factor</tt> (newly created)
     * @throws DifferentFieldsException if the elements are of different fields.
     */
    public GFElement multiply(GFElement factor)
        throws RuntimeException
    {
        GF2nONBElement result = new GF2nONBElement(this);
        result.multiplyThisBy(factor);
        return result;
    }

    /**
     * Compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
     *
     * @param factor the factor
     * @throws DifferentFieldsException if the elements are of different fields.
     */
    public void multiplyThisBy(GFElement factor)
        throws RuntimeException
    {

        if (!(factor instanceof GF2nONBElement))
        {
            throw new RuntimeException("The elements have different"
                + " representation: not yet" + " implemented");
        }
        if (!mField.equals(((GF2nONBElement)factor).mField))
        {
            throw new RuntimeException();
        }

        if (equals(factor))
        {
            squareThis();
        }
        else
        {

            long[] a = mPol;
            long[] b = ((GF2nONBElement)factor).mPol;
            long[] c = new long[mLength];

            int[][] m = ((GF2nONBField)mField).mMult;

            int degf, degb, s, fielda, fieldb, bita, bitb;
            degf = mLength - 1;
            degb = mBit - 1;
            s = 0;

            long TWOTOMAXLONGM1 = mBitmask[MAXLONG - 1];
            long TWOTODEGB = mBitmask[degb];

            boolean old, now;

            // the product c of a and b (a*b = c) is calculated in mDegree
            // cicles
            // in every cicle one coefficient of c is calculated and stored
            // k indicates the coefficient
            //
            for (int k = 0; k < mDegree; k++)
            {

                s = 0;

                for (int i = 0; i < mDegree; i++)
                {

                    // fielda = i / MAXLONG
                    //
                    fielda = mIBY64[i];

                    // bita = i % MAXLONG
                    //
                    bita = i & (MAXLONG - 1);

                    // fieldb = m[i][0] / MAXLONG
                    //
                    fieldb = mIBY64[m[i][0]];

                    // bitb = m[i][0] % MAXLONG
                    //
                    bitb = m[i][0] & (MAXLONG - 1);

                    if ((a[fielda] & mBitmask[bita]) != 0)
                    {

                        if ((b[fieldb] & mBitmask[bitb]) != 0)
                        {
                            s ^= 1;
                        }

                        if (m[i][1] != -1)
                        {

                            // fieldb = m[i][1] / MAXLONG
                            //
                            fieldb = mIBY64[m[i][1]];

                            // bitb = m[i][1] % MAXLONG
                            //
                            bitb = m[i][1] & (MAXLONG - 1);

                            if ((b[fieldb] & mBitmask[bitb]) != 0)
                            {
                                s ^= 1;
                            }

                        }
                    }
                }
                fielda = mIBY64[k];
                bita = k & (MAXLONG - 1);

                if (s != 0)
                {
                    c[fielda] ^= mBitmask[bita];
                }

                // Circular shift of x and y one bit to the right,
                // respectively.

                if (mLength > 1)
                {

                    // Shift x.
                    //
                    old = (a[degf] & 1) == 1;

                    for (int i = degf - 1; i >= 0; i--)
                    {
                        now = (a[i] & 1) != 0;

                        a[i] = a[i] >>> 1;

                        if (old)
                        {
                            a[i] ^= TWOTOMAXLONGM1;
                        }

                        old = now;
                    }
                    a[degf] = a[degf] >>> 1;

                    if (old)
                    {
                        a[degf] ^= TWOTODEGB;
                    }

                    // Shift y.
                    //
                    old = (b[degf] & 1) == 1;

                    for (int i = degf - 1; i >= 0; i--)
                    {
                        now = (b[i] & 1) != 0;

                        b[i] = b[i] >>> 1;

                        if (old)
                        {
                            b[i] ^= TWOTOMAXLONGM1;
                        }

                        old = now;
                    }

                    b[degf] = b[degf] >>> 1;

                    if (old)
                    {
                        b[degf] ^= TWOTODEGB;
                    }
                }
                else
                {
                    old = (a[0] & 1) == 1;
                    a[0] = a[0] >>> 1;

                    if (old)
                    {
                        a[0] ^= TWOTODEGB;
                    }

                    old = (b[0] & 1) == 1;
                    b[0] = b[0] >>> 1;

                    if (old)
                    {
                        b[0] ^= TWOTODEGB;
                    }
                }
            }
            assign(c);
        }
    }

    /**
     * returns <tt>this</tt> element to the power of 2.
     *
     * @return <tt>this</tt><sup>2</sup>
     */
    public GF2nElement square()
    {
        GF2nONBElement result = new GF2nONBElement(this);
        result.squareThis();
        return result;
    }

    /**
     * squares <tt>this</tt> element.
     */
    public void squareThis()
    {

        long[] pol = getElement();

        int f = mLength - 1;
        int b = mBit - 1;

        // Shift the coefficients one bit to the left.
        //
        long TWOTOMAXLONGM1 = mBitmask[MAXLONG - 1];
        boolean old, now;

        old = (pol[f] & mBitmask[b]) != 0;

        for (int i = 0; i < f; i++)
        {

            now = (pol[i] & TWOTOMAXLONGM1) != 0;

            pol[i] = pol[i] << 1;

            if (old)
            {
                pol[i] ^= 1;
            }

            old = now;
        }
        now = (pol[f] & mBitmask[b]) != 0;

        pol[f] = pol[f] << 1;

        if (old)
        {
            pol[f] ^= 1;
        }

        // Set the bit with index mDegree to zero.
        //
        if (now)
        {
            pol[f] ^= mBitmask[b + 1];
        }

        assign(pol);
    }

    /**
     * Compute the multiplicative inverse of this element.
     *
     * @return <tt>this<sup>-1</sup></tt> (newly created)
     * @throws ArithmeticException if <tt>this</tt> is the zero element.
     */
    public GFElement invert()
        throws ArithmeticException
    {
        GF2nONBElement result = new GF2nONBElement(this);
        result.invertThis();
        return result;
    }

    /**
     * Multiplicatively invert of this element (overwrite <tt>this</tt>).
     *
     * @throws ArithmeticException if <tt>this</tt> is the zero element.
     */
    public void invertThis()
        throws ArithmeticException
    {

        if (isZero())
        {
            throw new ArithmeticException();
        }
        int r = 31; // mDegree kann nur 31 Bits lang sein!!!

        // Bitlaenge von mDegree:
        for (boolean found = false; !found && r >= 0; r--)
        {

            if (((mDegree - 1) & mBitmask[r]) != 0)
            {
                found = true;
            }
        }
        r++;

        GF2nElement m = ZERO((GF2nONBField)mField);
        GF2nElement n = new GF2nONBElement(this);

        int k = 1;

        for (int i = r - 1; i >= 0; i--)
        {
            m = (GF2nElement)n.clone();
            for (int j = 1; j <= k; j++)
            {
                m.squareThis();
            }

            n.multiplyThisBy(m);

            k <<= 1;
            if (((mDegree - 1) & mBitmask[i]) != 0)
            {
                n.squareThis();

                n.multiplyThisBy(this);

                k++;
            }
        }
        n.squareThis();
    }

    /**
     * returns the root of<tt>this</tt> element.
     *
     * @return <tt>this</tt><sup>1/2</sup>
     */
    public GF2nElement squareRoot()
    {
        GF2nONBElement result = new GF2nONBElement(this);
        result.squareRootThis();
        return result;
    }

    /**
     * square roots <tt>this</tt> element.
     */
    public void squareRootThis()
    {

        long[] pol = getElement();

        int f = mLength - 1;
        int b = mBit - 1;

        // Shift the coefficients one bit to the right.
        //
        long TWOTOMAXLONGM1 = mBitmask[MAXLONG - 1];
        boolean old, now;

        old = (pol[0] & 1) != 0;

        for (int i = f; i >= 0; i--)
        {
            now = (pol[i] & 1) != 0;
            pol[i] = pol[i] >>> 1;

            if (old)
            {
                if (i == f)
                {
                    pol[i] ^= mBitmask[b];
                }
                else
                {
                    pol[i] ^= TWOTOMAXLONGM1;
                }
            }
            old = now;
        }
        assign(pol);
    }

    /**
     * Returns the trace of this element.
     *
     * @return the trace of this element
     */
    public int trace()
    {

        // trace = sum of coefficients
        //

        int result = 0;

        int max = mLength - 1;

        for (int i = 0; i < max; i++)
        {

            for (int j = 0; j < MAXLONG; j++)
            {

                if ((mPol[i] & mBitmask[j]) != 0)
                {
                    result ^= 1;
                }
            }
        }

        int b = mBit;

        for (int j = 0; j < b; j++)
        {

            if ((mPol[max] & mBitmask[j]) != 0)
            {
                result ^= 1;
            }
        }
        return result;
    }

    /**
     * Solves a quadratic equation.<br>
     * Let z<sup>2</sup> + z = <tt>this</tt>. Then this method returns z.
     *
     * @return z with z<sup>2</sup> + z = <tt>this</tt>
     * @throws NoSolutionException if z<sup>2</sup> + z = <tt>this</tt> does not have a
     * solution
     */
    public GF2nElement solveQuadraticEquation()
        throws RuntimeException
    {

        if (trace() == 1)
        {
            throw new RuntimeException();
        }

        long TWOTOMAXLONGM1 = mBitmask[MAXLONG - 1];
        long ZERO = 0L;
        long ONE = 1L;

        long[] p = new long[mLength];
        long z = 0L;
        int j = 1;
        for (int i = 0; i < mLength - 1; i++)
        {

            for (j = 1; j < MAXLONG; j++)
            {

                //
                if (!((((mBitmask[j] & mPol[i]) != ZERO) && ((z & mBitmask[j - 1]) != ZERO)) || (((mPol[i] & mBitmask[j]) == ZERO) && ((z & mBitmask[j - 1]) == ZERO))))
                {
                    z ^= mBitmask[j];
                }
            }
            p[i] = z;

            if (((TWOTOMAXLONGM1 & z) != ZERO && (ONE & mPol[i + 1]) == ONE)
                || ((TWOTOMAXLONGM1 & z) == ZERO && (ONE & mPol[i + 1]) == ZERO))
            {
                z = ZERO;
            }
            else
            {
                z = ONE;
            }
        }

        int b = mDegree & (MAXLONG - 1);

        long LASTLONG = mPol[mLength - 1];

        for (j = 1; j < b; j++)
        {
            if (!((((mBitmask[j] & LASTLONG) != ZERO) && ((mBitmask[j - 1] & z) != ZERO)) || (((mBitmask[j] & LASTLONG) == ZERO) && ((mBitmask[j - 1] & z) == ZERO))))
            {
                z ^= mBitmask[j];
            }
        }
        p[mLength - 1] = z;
        return new GF2nONBElement((GF2nONBField)mField, p);
    }

    // /////////////////////////////////////////////////////////////////
    // conversion
    // /////////////////////////////////////////////////////////////////

    /**
     * Returns a String representation of this element.
     *
     * @return String representation of this element with the specified radix
     */
    public String toString()
    {
        return toString(16);
    }

    /**
     * Returns a String representation of this element. <tt>radix</tt>
     * specifies the radix of the String representation.<br>
     * NOTE: ONLY <tt>radix = 2</tt> or <tt>radix = 16</tt> IS IMPLEMENTED
     *
     * @param radix specifies the radix of the String representation
     * @return String representation of this element with the specified radix
     */
    public String toString(int radix)
    {
        String s = "";

        long[] a = getElement();
        int b = mBit;

        if (radix == 2)
        {

            for (int j = b - 1; j >= 0; j--)
            {
                if ((a[a.length - 1] & ((long)1 << j)) == 0)
                {
                    s += "0";
                }
                else
                {
                    s += "1";
                }
            }

            for (int i = a.length - 2; i >= 0; i--)
            {
                for (int j = MAXLONG - 1; j >= 0; j--)
                {
                    if ((a[i] & mBitmask[j]) == 0)
                    {
                        s += "0";
                    }
                    else
                    {
                        s += "1";
                    }
                }
            }
        }
        else if (radix == 16)
        {
            final char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            for (int i = a.length - 1; i >= 0; i--)
            {
                s += HEX_CHARS[(int)(a[i] >>> 60) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 56) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 52) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 48) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 44) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 40) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 36) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 32) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 28) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 24) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 20) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 16) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 12) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 8) & 0x0f];
                s += HEX_CHARS[(int)(a[i] >>> 4) & 0x0f];
                s += HEX_CHARS[(int)(a[i]) & 0x0f];
                s += " ";
            }
        }
        return s;
    }

    /**
     * Returns this element as FlexiBigInt. The conversion is <a href =
     * "http://grouper.ieee.org/groups/1363/">P1363</a>-conform.
     *
     * @return this element as BigInteger
     */
    public BigInteger toFlexiBigInt()
    {
        /** @todo this method does not reverse the bit-order as it should!!! */

        return new BigInteger(1, toByteArray());
    }

    /**
     * Returns this element as byte array. The conversion is <a href =
     * "http://grouper.ieee.org/groups/1363/">P1363</a>-conform.
     *
     * @return this element as byte array
     */
    public byte[] toByteArray()
    {
        /** @todo this method does not reverse the bit-order as it should!!! */

        int k = ((mDegree - 1) >> 3) + 1;
        byte[] result = new byte[k];
        int i;
        for (i = 0; i < k; i++)
        {
            result[k - i - 1] = (byte)((mPol[i >>> 3] & (0x00000000000000ffL << ((i & 0x07) << 3))) >>> ((i & 0x07) << 3));
        }
        return result;
    }

}
