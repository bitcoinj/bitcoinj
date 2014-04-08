package org.bouncycastle.pqc.math.ntru.polynomial;

import java.math.BigInteger;

import org.bouncycastle.pqc.math.ntru.euclid.BigIntEuclidean;

/**
 * A resultant modulo a <code>BigInteger</code>
 */
public class ModularResultant
    extends Resultant
{
    BigInteger modulus;

    ModularResultant(BigIntPolynomial rho, BigInteger res, BigInteger modulus)
    {
        super(rho, res);
        this.modulus = modulus;
    }

    /**
     * Calculates a <code>rho</code> modulo <code>m1*m2</code> from
     * two resultants whose <code>rho</code>s are modulo <code>m1</code> and <code>m2</code>.<br/>
     * </code>res</code> is set to <code>null</code>.
     *
     * @param modRes1
     * @param modRes2
     * @return <code>rho</code> modulo <code>modRes1.modulus * modRes2.modulus</code>, and <code>null</code> for </code>res</code>.
     */
    static ModularResultant combineRho(ModularResultant modRes1, ModularResultant modRes2)
    {
        BigInteger mod1 = modRes1.modulus;
        BigInteger mod2 = modRes2.modulus;
        BigInteger prod = mod1.multiply(mod2);
        BigIntEuclidean er = BigIntEuclidean.calculate(mod2, mod1);

        BigIntPolynomial rho1 = (BigIntPolynomial)modRes1.rho.clone();
        rho1.mult(er.x.multiply(mod2));
        BigIntPolynomial rho2 = (BigIntPolynomial)modRes2.rho.clone();
        rho2.mult(er.y.multiply(mod1));
        rho1.add(rho2);
        rho1.mod(prod);

        return new ModularResultant(rho1, null, prod);
    }
}
