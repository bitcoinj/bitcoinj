package org.bouncycastle.crypto.engines;

/**
 * An implementation of the Camellia key wrapper based on RFC 3657/RFC 3394.
 * <p>
 * For further details see: <a href="http://www.ietf.org/rfc/rfc3657.txt">http://www.ietf.org/rfc/rfc3657.txt</a>.
 */
public class CamelliaWrapEngine
    extends RFC3394WrapEngine
{
    public CamelliaWrapEngine()
    {
        super(new CamelliaEngine());
    }
}
