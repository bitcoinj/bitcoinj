package org.bouncycastle.pqc.crypto.mceliece;


import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * This class provides a specification for the parameters of the CCA2-secure
 * variants of the McEliece PKCS that are used with
 * {@link McElieceFujisakiCipher}, {@link McElieceKobaraImaiCipher}, and
 * {@link McEliecePointchevalCipher}.
 *
 * @see McElieceFujisakiCipher
 * @see McElieceKobaraImaiCipher
 * @see McEliecePointchevalCipher
 */
public class McElieceCCA2Parameters
    extends McElieceParameters
{


    public Digest digest;


    /**
     * Construct the default parameters.
     * The default message digest is SHA256.
     */
    public McElieceCCA2Parameters()
    {
        this.digest = new SHA256Digest();
    }

    public McElieceCCA2Parameters(int m, int t)
    {
        super(m, t);
        this.digest = new SHA256Digest();
    }

    public McElieceCCA2Parameters(Digest digest)
    {
        this.digest = digest;
    }

    public Digest getDigest()
    {
        return this.digest;
    }


}
