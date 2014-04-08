package org.bouncycastle.asn1;

import java.io.IOException;

public class ASN1Exception
    extends IOException
{
    private Throwable cause;

    ASN1Exception(String message)
    {
        super(message);
    }

    ASN1Exception(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
