package com.google.bitcoin.bouncycastle.crypto.tls;

import com.google.bitcoin.bouncycastle.asn1.x509.X509CertificateStructure;

/**
 * A certificate verifyer, that will always return true.
 * <pre>
 * DO NOT USE THIS FILE UNLESS YOU KNOW EXACTLY WHAT YOU ARE DOING.
 * </pre>
 */
public class AlwaysValidVerifyer implements CertificateVerifyer
{

    /**
     * Return true.
     *
     * @see com.google.bitcoin.bouncycastle.crypto.tls.CertificateVerifyer#isValid(com.google.bitcoin.bouncycastle.asn1.x509.X509CertificateStructure[])
     */
    public boolean isValid(X509CertificateStructure[] certs)
    {
        return true;
    }

}
