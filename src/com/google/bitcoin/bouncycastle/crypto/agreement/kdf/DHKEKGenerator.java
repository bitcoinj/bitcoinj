package com.google.bitcoin.bouncycastle.crypto.agreement.kdf;

import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.DERObjectIdentifier;
import com.google.bitcoin.bouncycastle.asn1.DEROctetString;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;
import com.google.bitcoin.bouncycastle.crypto.DataLengthException;
import com.google.bitcoin.bouncycastle.crypto.DerivationFunction;
import com.google.bitcoin.bouncycastle.crypto.DerivationParameters;
import com.google.bitcoin.bouncycastle.crypto.Digest;

/**
 * RFC 2631 Diffie-hellman KEK derivation function.
 */
public class DHKEKGenerator
    implements DerivationFunction
{
    private final Digest digest;

    private DERObjectIdentifier algorithm;
    private int                 keySize;
    private byte[]              z;
    private byte[]              partyAInfo;

    public DHKEKGenerator(
        Digest digest)
    {
        this.digest = digest;
    }

    public void init(DerivationParameters param)
    {
        DHKDFParameters params = (DHKDFParameters)param;

        this.algorithm = params.getAlgorithm();
        this.keySize = params.getKeySize();
        this.z = params.getZ();
        this.partyAInfo = params.getExtraInfo();
    }

    public Digest getDigest()
    {
        return digest;
    }

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException
    {
        if ((out.length - len) < outOff)
        {
            throw new DataLengthException("output buffer too small");
        }

        long    oBytes = len;
        int     outLen = digest.getDigestSize();

        //
        // this is at odds with the standard implementation, the
        // maximum value should be hBits * (2^32 - 1) where hBits
        // is the digest output size in bits. We can't have an
        // array with a long index at the moment...
        //
        if (oBytes > ((2L << 32) - 1))
        {
            throw new IllegalArgumentException("Output length too large");
        }

        int cThreshold = (int)((oBytes + outLen - 1) / outLen);

        byte[] dig = new byte[digest.getDigestSize()];

        int counter = 1;

        for (int i = 0; i < cThreshold; i++)
        {
            digest.update(z, 0, z.length);

            // OtherInfo
            ASN1EncodableVector v1 = new ASN1EncodableVector();
            // KeySpecificInfo
            ASN1EncodableVector v2 = new ASN1EncodableVector();

            v2.add(algorithm);
            v2.add(new DEROctetString(integerToBytes(counter)));

            v1.add(new DERSequence(v2));

            if (partyAInfo != null)
            {
                v1.add(new DERTaggedObject(true, 0, new DEROctetString(partyAInfo)));
            }

            v1.add(new DERTaggedObject(true, 2, new DEROctetString(integerToBytes(keySize))));

            byte[] other = new DERSequence(v1).getDEREncoded();

            digest.update(other, 0, other.length);

            digest.doFinal(dig, 0);

            if (len > outLen)
            {
                System.arraycopy(dig, 0, out, outOff, outLen);
                outOff += outLen;
                len -= outLen;
            }
            else
            {
                System.arraycopy(dig, 0, out, outOff, len);
            }

            counter++;
        }

        digest.reset();

        return len;
    }

    private byte[] integerToBytes(int keySize)
    {
        byte[] val = new byte[4];

        val[0] = (byte)(keySize >> 24);
        val[1] = (byte)(keySize >> 16);
        val[2] = (byte)(keySize >> 8);
        val[3] = (byte)keySize;

        return val;
    }
}
