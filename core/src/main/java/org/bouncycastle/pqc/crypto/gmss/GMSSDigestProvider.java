package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.crypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}
