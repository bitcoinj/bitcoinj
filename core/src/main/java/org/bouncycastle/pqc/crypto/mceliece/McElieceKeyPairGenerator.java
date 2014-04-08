package org.bouncycastle.pqc.crypto.mceliece;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode.MaMaPe;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2m;


/**
 * This class implements key pair generation of the McEliece Public Key
 * Cryptosystem (McEliecePKC).
 */
public class McElieceKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{


    public McElieceKeyPairGenerator()
    {

    }


    /**
     * The OID of the algorithm.
     */
    private static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";

    private McElieceKeyGenerationParameters mcElieceParams;

    // the extension degree of the finite field GF(2^m)
    private int m;

    // the length of the code
    private int n;

    // the error correction capability
    private int t;

    // the field polynomial
    private int fieldPoly;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized = false;


    /**
     * Default initialization of the key pair generator.
     */
    private void initializeDefault()
    {
        McElieceKeyGenerationParameters mcParams = new McElieceKeyGenerationParameters(new SecureRandom(), new McElieceParameters());
        initialize(mcParams);
    }

    private void initialize(
        KeyGenerationParameters param)
    {
        this.mcElieceParams = (McElieceKeyGenerationParameters)param;

        // set source of randomness
        this.random = new SecureRandom();

        this.m = this.mcElieceParams.getParameters().getM();
        this.n = this.mcElieceParams.getParameters().getN();
        this.t = this.mcElieceParams.getParameters().getT();
        this.fieldPoly = this.mcElieceParams.getParameters().getFieldPoly();
        this.initialized = true;
    }


    private AsymmetricCipherKeyPair genKeyPair()
    {

        if (!initialized)
        {
            initializeDefault();
        }

        // finite field GF(2^m)
        GF2mField field = new GF2mField(m, fieldPoly);

        // irreducible Goppa polynomial
        PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, t,
            PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, random);
        PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

        // matrix used to compute square roots in (GF(2^m))^t
        PolynomialGF2mSmallM[] sqRootMatrix = ring.getSquareRootMatrix();

        // generate canonical check matrix
        GF2Matrix h = GoppaCode.createCanonicalCheckMatrix(field, gp);

        // compute short systematic form of check matrix
        MaMaPe mmp = GoppaCode.computeSystematicForm(h, random);
        GF2Matrix shortH = mmp.getSecondMatrix();
        Permutation p1 = mmp.getPermutation();

        // compute short systematic form of generator matrix
        GF2Matrix shortG = (GF2Matrix)shortH.computeTranspose();

        // extend to full systematic form
        GF2Matrix gPrime = shortG.extendLeftCompactForm();

        // obtain number of rows of G (= dimension of the code)
        int k = shortG.getNumRows();

        // generate random invertible (k x k)-matrix S and its inverse S^-1
        GF2Matrix[] matrixSandInverse = GF2Matrix
            .createRandomRegularMatrixAndItsInverse(k, random);

        // generate random permutation P2
        Permutation p2 = new Permutation(n, random);

        // compute public matrix G=S*G'*P2
        GF2Matrix g = (GF2Matrix)matrixSandInverse[0].rightMultiply(gPrime);
        g = (GF2Matrix)g.rightMultiply(p2);


        // generate keys
        McEliecePublicKeyParameters pubKey = new McEliecePublicKeyParameters(OID, n, t, g, mcElieceParams.getParameters());
        McEliecePrivateKeyParameters privKey = new McEliecePrivateKeyParameters(OID, n, k,
            field, gp, matrixSandInverse[1], p1, p2, h, sqRootMatrix, mcElieceParams.getParameters());

        // return key pair
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);

    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }

}
