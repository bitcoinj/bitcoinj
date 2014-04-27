package com.subgraph.orchid.encoders;

public class DecoderException
    extends IllegalStateException
{
	private static final long serialVersionUID = 4997418733670548381L;
	private Throwable cause;

    DecoderException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
