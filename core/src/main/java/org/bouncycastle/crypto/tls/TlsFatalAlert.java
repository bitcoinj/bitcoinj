package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class TlsFatalAlert
    extends IOException
{
    private static final long serialVersionUID = 3584313123679111168L;

    private short alertDescription;

    public TlsFatalAlert(short alertDescription)
    {
        this.alertDescription = alertDescription;
    }

    public short getAlertDescription()
    {
        return alertDescription;
    }
}
