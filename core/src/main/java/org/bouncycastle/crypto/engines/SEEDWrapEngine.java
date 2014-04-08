package org.bouncycastle.crypto.engines;

/**
 * An implementation of the SEED key wrapper based on RFC 4010/RFC 3394.
 * <p>
 * For further details see: <a href="http://www.ietf.org/rfc/rfc4010.txt">http://www.ietf.org/rfc/rfc4010.txt</a>.
 */
public class SEEDWrapEngine
    extends RFC3394WrapEngine
{
    public SEEDWrapEngine()
    {
        super(new SEEDEngine());
    }
}
