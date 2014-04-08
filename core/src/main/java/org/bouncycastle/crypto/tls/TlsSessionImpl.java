package org.bouncycastle.crypto.tls;

import org.bouncycastle.util.Arrays;

class TlsSessionImpl implements TlsSession
{
    final byte[] sessionID;
    SessionParameters sessionParameters;

    TlsSessionImpl(byte[] sessionID, SessionParameters sessionParameters)
    {
        if (sessionID == null)
        {
            throw new IllegalArgumentException("'sessionID' cannot be null");
        }
        if (sessionID.length < 1 || sessionID.length > 32)
        {
            throw new IllegalArgumentException("'sessionID' must have length between 1 and 32 bytes, inclusive");
        }

        this.sessionID = Arrays.clone(sessionID);
        this.sessionParameters = sessionParameters;
    }

    public synchronized SessionParameters exportSessionParameters()
    {
        return this.sessionParameters == null ? null : this.sessionParameters.copy();
    }

    public synchronized byte[] getSessionID()
    {
        return sessionID;
    }

    public synchronized void invalidate()
    {
        if (this.sessionParameters != null)
        {
            this.sessionParameters.clear();
            this.sessionParameters = null;
        }
    }

    public synchronized boolean isResumable()
    {
        return this.sessionParameters != null;
    }
}
