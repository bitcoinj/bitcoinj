package org.bouncycastle.pqc.crypto.rainbow.util;

/**
 * This class provides the basic operations like addition, multiplication and
 * finding the multiplicative inverse of an element in GF2^8.
 * <p>
 * The operations are implemented using the irreducible polynomial
 * 1+x^2+x^3+x^6+x^8 ( 1 0100 1101 = 0x14d )
 * <p>
 * This class makes use of lookup tables(exps and logs) for implementing the
 * operations in order to increase the efficiency of Rainbow.
 */
public class GF2Field
{

    public static final int MASK = 0xff;

    /*
      * this lookup table is needed for multiplication and computing the
      * multiplicative inverse
      */
    static final short exps[] = {1, 2, 4, 8, 16, 32, 64, 128, 77, 154, 121, 242,
        169, 31, 62, 124, 248, 189, 55, 110, 220, 245, 167, 3, 6, 12, 24,
        48, 96, 192, 205, 215, 227, 139, 91, 182, 33, 66, 132, 69, 138, 89,
        178, 41, 82, 164, 5, 10, 20, 40, 80, 160, 13, 26, 52, 104, 208,
        237, 151, 99, 198, 193, 207, 211, 235, 155, 123, 246, 161, 15, 30,
        60, 120, 240, 173, 23, 46, 92, 184, 61, 122, 244, 165, 7, 14, 28,
        56, 112, 224, 141, 87, 174, 17, 34, 68, 136, 93, 186, 57, 114, 228,
        133, 71, 142, 81, 162, 9, 18, 36, 72, 144, 109, 218, 249, 191, 51,
        102, 204, 213, 231, 131, 75, 150, 97, 194, 201, 223, 243, 171, 27,
        54, 108, 216, 253, 183, 35, 70, 140, 85, 170, 25, 50, 100, 200,
        221, 247, 163, 11, 22, 44, 88, 176, 45, 90, 180, 37, 74, 148, 101,
        202, 217, 255, 179, 43, 86, 172, 21, 42, 84, 168, 29, 58, 116, 232,
        157, 119, 238, 145, 111, 222, 241, 175, 19, 38, 76, 152, 125, 250,
        185, 63, 126, 252, 181, 39, 78, 156, 117, 234, 153, 127, 254, 177,
        47, 94, 188, 53, 106, 212, 229, 135, 67, 134, 65, 130, 73, 146,
        105, 210, 233, 159, 115, 230, 129, 79, 158, 113, 226, 137, 95, 190,
        49, 98, 196, 197, 199, 195, 203, 219, 251, 187, 59, 118, 236, 149,
        103, 206, 209, 239, 147, 107, 214, 225, 143, 83, 166, 1};

    /*
      * this lookup table is needed for multiplication and computing the
      * multiplicative inverse
      */
    static final short logs[] = {0, 0, 1, 23, 2, 46, 24, 83, 3, 106, 47, 147,
        25, 52, 84, 69, 4, 92, 107, 182, 48, 166, 148, 75, 26, 140, 53,
        129, 85, 170, 70, 13, 5, 36, 93, 135, 108, 155, 183, 193, 49, 43,
        167, 163, 149, 152, 76, 202, 27, 230, 141, 115, 54, 205, 130, 18,
        86, 98, 171, 240, 71, 79, 14, 189, 6, 212, 37, 210, 94, 39, 136,
        102, 109, 214, 156, 121, 184, 8, 194, 223, 50, 104, 44, 253, 168,
        138, 164, 90, 150, 41, 153, 34, 77, 96, 203, 228, 28, 123, 231, 59,
        142, 158, 116, 244, 55, 216, 206, 249, 131, 111, 19, 178, 87, 225,
        99, 220, 172, 196, 241, 175, 72, 10, 80, 66, 15, 186, 190, 199, 7,
        222, 213, 120, 38, 101, 211, 209, 95, 227, 40, 33, 137, 89, 103,
        252, 110, 177, 215, 248, 157, 243, 122, 58, 185, 198, 9, 65, 195,
        174, 224, 219, 51, 68, 105, 146, 45, 82, 254, 22, 169, 12, 139,
        128, 165, 74, 91, 181, 151, 201, 42, 162, 154, 192, 35, 134, 78,
        188, 97, 239, 204, 17, 229, 114, 29, 61, 124, 235, 232, 233, 60,
        234, 143, 125, 159, 236, 117, 30, 245, 62, 56, 246, 217, 63, 207,
        118, 250, 31, 132, 160, 112, 237, 20, 144, 179, 126, 88, 251, 226,
        32, 100, 208, 221, 119, 173, 218, 197, 64, 242, 57, 176, 247, 73,
        180, 11, 127, 81, 21, 67, 145, 16, 113, 187, 238, 191, 133, 200,
        161};

    /**
     * This function calculates the sum of two elements as an operation in GF2^8
     *
     * @param x the first element that is to be added
     * @param y the second element that should be add
     * @return the sum of the two elements x and y in GF2^8
     */
    public static short addElem(short x, short y)
    {
        return (short)(x ^ y);
    }

    /**
     * This function computes the multiplicative inverse of a given element in
     * GF2^8 The 0 has no multiplicative inverse and in this case 0 is returned.
     *
     * @param x the element which multiplicative inverse is to be computed
     * @return the multiplicative inverse of the given element, in case it
     *         exists or 0, otherwise
     */
    public static short invElem(short x)
    {
        if (x == 0)
        {
            return 0;
        }
        return (exps[255 - logs[x]]);
    }

    /**
     * This function multiplies two elements in GF2^8. If one of the two
     * elements is 0, 0 is returned.
     *
     * @param x the first element to be multiplied.
     * @param y the second element to be multiplied.
     * @return the product of the two input elements in GF2^8.
     */
    public static short multElem(short x, short y)
    {
        if (x == 0 || y == 0)
        {
            return 0;
        }
        else
        {
            return (exps[(logs[x] + logs[y]) % 255]);
        }
    }

    /**
     * This function returns the values of exps-lookup table which correspond to
     * the input
     *
     * @param x the index in the lookup table exps
     * @return exps-value, corresponding to the input
     */
    public static short getExp(short x)
    {
        return exps[x];
    }

    /**
     * This function returns the values of logs-lookup table which correspond to
     * the input
     *
     * @param x the index in the lookup table logs
     * @return logs-value, corresponding to the input
     */
    public static short getLog(short x)
    {
        return logs[x];
    }


}
