package com.google.bitcoin.bouncycastle.crypto.tls;

import com.google.bitcoin.bouncycastle.asn1.x509.X509CertificateStructure;

/**
 * This should be implemented by any class which can find out, if a given
 * certificate chain is beeing accepted by an client.
 */
public interface CertificateVerifyer
{
    /**
     * @param certs The certs, which are part of the chain.
     * @return True, if the chain is accepted, false otherwise.
     */
    public boolean isValid(X509CertificateStructure[] certs);
}
