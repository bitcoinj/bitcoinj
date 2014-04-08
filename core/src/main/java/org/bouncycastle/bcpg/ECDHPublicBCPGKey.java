package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECPoint;

/**
 * base class for an ECDH Public Key.
 */
public class ECDHPublicBCPGKey
    extends ECPublicBCPGKey
{
    private byte reserved;
    private byte hashFunctionId;
    private byte symAlgorithmId;

    /**
     * @param in the stream to read the packet from.
     */
    public ECDHPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);

        int length = in.read();
        byte[] kdfParameters =  new byte[length];
        if (kdfParameters.length != 3)
        {
            throw new IllegalStateException("kdf parameters size of 3 expected.");
        }

        in.read(kdfParameters);

        reserved = kdfParameters[0];
        hashFunctionId = kdfParameters[1];
        symAlgorithmId = kdfParameters[2];

        verifyHashAlgorithm();
        verifySymmetricKeyAlgorithm();
    }

    public ECDHPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point,
        int hashAlgorithm,
        int symmetricKeyAlgorithm)
    {
        super(oid, point);

        reserved = 1;
        hashFunctionId = (byte)hashAlgorithm;
        symAlgorithmId = (byte)symmetricKeyAlgorithm;

        verifyHashAlgorithm();
        verifySymmetricKeyAlgorithm();
    }

    public byte getReserved()
    {
        return reserved;
    }

    public byte getHashAlgorithm()
    {
        return hashFunctionId;
    }

    public byte getSymmetricKeyAlgorithm()
    {
        return symAlgorithmId;
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        super.encode(out);
        out.write(0x3);
        out.write(reserved);
        out.write(hashFunctionId);
        out.write(symAlgorithmId);
    }

    private void verifyHashAlgorithm()
    {
        switch (hashFunctionId)
        {
        case HashAlgorithmTags.SHA256:
        case HashAlgorithmTags.SHA384:
        case HashAlgorithmTags.SHA512:
            break;

        default:
            throw new IllegalStateException("Hash algorithm must be SHA-256 or stronger.");
        }
    }

    private void verifySymmetricKeyAlgorithm()
    {
        switch (symAlgorithmId)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.AES_256:
            break;

        default:
            throw new IllegalStateException("Symmetric key algorithm must be AES-128 or stronger.");
        }
    }
}
