package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class HeartbeatExtension
{
    protected short mode;

    public HeartbeatExtension(short mode)
    {
        if (!HeartbeatMode.isValid(mode))
        {
            throw new IllegalArgumentException("'mode' is not a valid HeartbeatMode value");
        }

        this.mode = mode;
    }

    public short getMode()
    {
        return mode;
    }

    /**
     * Encode this {@link HeartbeatExtension} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(mode, output);
    }

    /**
     * Parse a {@link HeartbeatExtension} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link HeartbeatExtension} object.
     * @throws IOException
     */
    public static HeartbeatExtension parse(InputStream input) throws IOException
    {
        short mode = TlsUtils.readUint8(input);
        if (!HeartbeatMode.isValid(mode))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return new HeartbeatExtension(mode);
    }
}
