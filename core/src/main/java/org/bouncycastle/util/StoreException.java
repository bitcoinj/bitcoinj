package org.bouncycastle.util;

public class StoreException
    extends RuntimeException
{
    private Throwable _e;

    public StoreException(String s, Throwable e)
    {
        super(s);
        _e = e;
    }

    public Throwable getCause()
    {
        return _e;
    }
}
