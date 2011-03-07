package com.google.bitcoin.bouncycastle.asn1;

public class ASN1ParsingException
    extends IllegalStateException
{
    private Throwable cause;

    ASN1ParsingException(String message)
    {
        super(message);
    }

    ASN1ParsingException(String message, Throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
