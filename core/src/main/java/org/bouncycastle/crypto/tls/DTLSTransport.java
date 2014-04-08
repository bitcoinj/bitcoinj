package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class DTLSTransport
    implements DatagramTransport
{
    private final DTLSRecordLayer recordLayer;

    DTLSTransport(DTLSRecordLayer recordLayer)
    {
        this.recordLayer = recordLayer;
    }

    public int getReceiveLimit()
        throws IOException
    {
        return recordLayer.getReceiveLimit();
    }

    public int getSendLimit()
        throws IOException
    {
        return recordLayer.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        try
        {
            return recordLayer.receive(buf, off, len, waitMillis);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            recordLayer.fail(fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (IOException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        try
        {
            recordLayer.send(buf, off, len);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            recordLayer.fail(fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (IOException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void close()
        throws IOException
    {
        recordLayer.close();
    }
}
