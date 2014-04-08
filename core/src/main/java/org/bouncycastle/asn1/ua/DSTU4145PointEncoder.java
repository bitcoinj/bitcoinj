package org.bouncycastle.asn1.ua;

import java.math.BigInteger;
import java.util.Random;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * DSTU4145 encodes points somewhat differently than X9.62
 * It compresses the point to the size of the field element
 */
public abstract class DSTU4145PointEncoder
{
    private static ECFieldElement trace(ECFieldElement fe)
    {
        ECFieldElement t = fe;
        for (int i = 1; i < fe.getFieldSize(); ++i)
        {
            t = t.square().add(fe);
        }
        return t;
    }

    /**
     * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
     * D.1.6) The other solution is <code>z + 1</code>.
     *
     * @param beta The value to solve the quadratic equation for.
     * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
     *         <code>null</code> if no solution exists.
     */
    private static ECFieldElement solveQuadraticEquation(ECCurve curve, ECFieldElement beta)
    {
        if (beta.isZero())
        {
            return beta;
        }

        ECFieldElement zeroElement = curve.fromBigInteger(ECConstants.ZERO);

        ECFieldElement z = null;
        ECFieldElement gamma = null;

        Random rand = new Random();
        int m = beta.getFieldSize();
        do
        {
            ECFieldElement t = curve.fromBigInteger(new BigInteger(m, rand));
            z = zeroElement;
            ECFieldElement w = beta;
            for (int i = 1; i <= m - 1; i++)
            {
                ECFieldElement w2 = w.square();
                z = z.square().add(w2.multiply(t));
                w = w2.add(beta);
            }
            if (!w.isZero())
            {
                return null;
            }
            gamma = z.square().add(z);
        }
        while (gamma.isZero());

        return z;
    }

    public static byte[] encodePoint(ECPoint Q)
    {
        /*if (!Q.isCompressed())
              Q=new ECPoint.F2m(Q.getCurve(),Q.getX(),Q.getY(),true);

          byte[] bytes=Q.getEncoded();

          if (bytes[0]==0x02)
              bytes[bytes.length-1]&=0xFE;
          else if (bytes[0]==0x02)
              bytes[bytes.length-1]|=0x01;

          return Arrays.copyOfRange(bytes, 1, bytes.length);*/

        Q = Q.normalize();

        ECFieldElement x = Q.getAffineXCoord();

        byte[] bytes = x.getEncoded();

        if (!x.isZero())
        {
            ECFieldElement z = Q.getAffineYCoord().divide(x);
            if (trace(z).isOne())
            {
                bytes[bytes.length - 1] |= 0x01;
            }
            else
            {
                bytes[bytes.length - 1] &= 0xFE;
            }
        }

        return bytes;
    }

    public static ECPoint decodePoint(ECCurve curve, byte[] bytes)
    {
        /*byte[] bp_enc=new byte[bytes.length+1];
          if (0==(bytes[bytes.length-1]&0x1))
              bp_enc[0]=0x02;
          else
              bp_enc[0]=0x03;
          System.arraycopy(bytes, 0, bp_enc, 1, bytes.length);
          if (!trace(curve.fromBigInteger(new BigInteger(1, bytes))).equals(curve.getA().toBigInteger()))
              bp_enc[bp_enc.length-1]^=0x01;

          return curve.decodePoint(bp_enc);*/

        ECFieldElement k = curve.fromBigInteger(BigInteger.valueOf(bytes[bytes.length - 1] & 0x1));

        ECFieldElement xp = curve.fromBigInteger(new BigInteger(1, bytes));
        if (!trace(xp).equals(curve.getA()))
        {
            xp = xp.addOne();
        }

        ECFieldElement yp;
        if (xp.isZero())
        {
            yp = curve.getB().sqrt();
        }
        else
        {
            ECFieldElement beta = xp.square().invert().multiply(curve.getB()).add(curve.getA()).add(xp);
            ECFieldElement z = solveQuadraticEquation(curve, beta);
            if (z == null)
            {
                throw new RuntimeException("Invalid point compression");
            }
            if (!trace(z).equals(k))
            {
                z = z.addOne();
            }
            yp = xp.multiply(z);
        }

        return curve.createPoint(xp.toBigInteger(), yp.toBigInteger());
    }
}
