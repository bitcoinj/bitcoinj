package com.google.bitcoin.bouncycastle.crypto.tls;

public class TlsRuntimeException
    extends RuntimeException
{
    Throwable e;

    public TlsRuntimeException(String message, Throwable e)
    {
        super(message);

        this.e = e;
    }

    public TlsRuntimeException(String message)
    {
        super(message);
    }

    public Throwable getCause()
    {
        return e;
    }
}
