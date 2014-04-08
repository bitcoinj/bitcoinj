package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface TlsCipher
{
    int getPlaintextLimit(int ciphertextLimit);

    byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException;

    byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException;
}
