package com.google.bitcoin.bouncycastle.crypto.tls;

import com.google.bitcoin.bouncycastle.crypto.encodings.PKCS1Encoding;
import com.google.bitcoin.bouncycastle.crypto.engines.RSABlindedEngine;
import com.google.bitcoin.bouncycastle.crypto.signers.GenericSigner;

class TlsRSASigner
    extends GenericSigner
{
    TlsRSASigner()
    {
        super(new PKCS1Encoding(new RSABlindedEngine()), new CombinedHash());
    }
}
