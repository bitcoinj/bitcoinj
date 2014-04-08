package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Strings;

/**
 * RFC 6066 5.
 */
public class URLAndHash
{
    protected String url;
    protected byte[] sha1Hash;

    public URLAndHash(String url, byte[] sha1Hash)
    {
        if (url == null || url.length() < 1 || url.length() >= (1 << 16))
        {
            throw new IllegalArgumentException("'url' must have length from 1 to (2^16 - 1)");
        }
        if (sha1Hash != null && sha1Hash.length != 20)
        {
            throw new IllegalArgumentException("'sha1Hash' must have length == 20, if present");
        }

        this.url = url;
        this.sha1Hash = sha1Hash;
    }

    public String getURL()
    {
        return url;
    }

    public byte[] getSHA1Hash()
    {
        return sha1Hash;
    }

    /**
     * Encode this {@link URLAndHash} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        byte[] urlEncoding = Strings.toByteArray(this.url);
        TlsUtils.writeOpaque16(urlEncoding, output);

        if (this.sha1Hash == null)
        {
            TlsUtils.writeUint8(0, output);
        }
        else
        {
            TlsUtils.writeUint8(1, output);
            output.write(this.sha1Hash);
        }
    }

    /**
     * Parse a {@link URLAndHash} from an {@link InputStream}.
     * 
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link URLAndHash} object.
     * @throws IOException
     */
    public static URLAndHash parse(TlsContext context, InputStream input)
        throws IOException
    {
        byte[] urlEncoding = TlsUtils.readOpaque16(input);
        if (urlEncoding.length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        String url = Strings.fromByteArray(urlEncoding);

        byte[] sha1Hash = null;
        short padding = TlsUtils.readUint8(input);
        switch (padding)
        {
        case 0:
            if (TlsUtils.isTLSv12(context))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            break;
        case 1:
            sha1Hash = TlsUtils.readFully(20, input);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return new URLAndHash(url, sha1Hash);
    }
}
