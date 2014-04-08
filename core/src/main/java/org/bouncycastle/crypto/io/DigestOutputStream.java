package org.bouncycastle.crypto.io;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Digest;

public class DigestOutputStream
    extends OutputStream
{
    protected Digest digest;

    public DigestOutputStream(
        Digest          Digest)
    {
        this.digest = Digest;
    }

    public void write(int b)
        throws IOException
    {
        digest.update((byte)b);
    }

    public void write(
        byte[] b,
        int off,
        int len)
        throws IOException
    {
        digest.update(b, off, len);
    }

    public byte[] getDigest()
    {
        byte[] res = new byte[digest.getDigestSize()];
        
        digest.doFinal(res, 0);
        
        return res;
    }
}
