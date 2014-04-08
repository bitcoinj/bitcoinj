package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.Signer;

class SignerInputBuffer extends ByteArrayOutputStream
{
    void updateSigner(Signer s)
    {
        s.update(this.buf, 0, count);
    }
}