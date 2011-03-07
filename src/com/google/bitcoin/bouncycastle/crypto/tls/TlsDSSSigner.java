package com.google.bitcoin.bouncycastle.crypto.tls;

import com.google.bitcoin.bouncycastle.crypto.digests.SHA1Digest;
import com.google.bitcoin.bouncycastle.crypto.signers.DSADigestSigner;
import com.google.bitcoin.bouncycastle.crypto.signers.DSASigner;

class TlsDSSSigner
    extends DSADigestSigner
{
    TlsDSSSigner()
    {
        super(new DSASigner(), new SHA1Digest());
    }
}
