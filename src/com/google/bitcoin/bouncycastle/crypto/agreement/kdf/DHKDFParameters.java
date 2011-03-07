package com.google.bitcoin.bouncycastle.crypto.agreement.kdf;

import com.google.bitcoin.bouncycastle.asn1.DERObjectIdentifier;
import com.google.bitcoin.bouncycastle.crypto.DerivationParameters;

public class DHKDFParameters
    implements DerivationParameters
{
    private final DERObjectIdentifier algorithm;
    private final int keySize;
    private final byte[] z;
    private final byte[] extraInfo;

    public DHKDFParameters(
        DERObjectIdentifier algorithm,
        int keySize,
        byte[] z)
    {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.z = z;
        this.extraInfo = null;
    }

    public DHKDFParameters(
        DERObjectIdentifier algorithm,
        int keySize,
        byte[] z,
        byte[] extraInfo)
    {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.z = z;
        this.extraInfo = extraInfo;
    }

    public DERObjectIdentifier getAlgorithm()
    {
        return algorithm;
    }

    public int getKeySize()
    {
        return keySize;
    }

    public byte[] getZ()
    {
        return z;
    }

    public byte[] getExtraInfo()
    {
        return extraInfo;
    }
}
