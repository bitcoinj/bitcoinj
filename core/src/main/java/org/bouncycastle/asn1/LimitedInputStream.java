package org.bouncycastle.asn1;

import java.io.InputStream;

abstract class LimitedInputStream
        extends InputStream
{
    protected final InputStream _in;
    private int _limit;

    LimitedInputStream(
        InputStream in,
        int         limit)
    {
        this._in = in;
        this._limit = limit;
    }

    int getRemaining()
    {
        // TODO: maybe one day this can become more accurate
        return _limit;
    }
    
    protected void setParentEofDetect(boolean on)
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(on);
        }
    }
}
