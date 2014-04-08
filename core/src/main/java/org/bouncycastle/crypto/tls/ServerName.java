package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Strings;

public class ServerName
{
    protected short nameType;
    protected Object name;

    public ServerName(short nameType, Object name)
    {
        if (!isCorrectType(nameType, name))
        {
            throw new IllegalArgumentException("'name' is not an instance of the correct type");
        }

        this.nameType = nameType;
        this.name = name;
    }

    public short getNameType()
    {
        return nameType;
    }

    public Object getName()
    {
        return name;
    }

    public String getHostName()
    {
        if (!isCorrectType(NameType.host_name, name))
        {
            throw new IllegalStateException("'name' is not a HostName string");
        }
        return (String)name;
    }

    /**
     * Encode this {@link ServerName} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(nameType, output);

        switch (nameType)
        {
        case NameType.host_name:
            byte[] utf8Encoding = Strings.toUTF8ByteArray((String)name);
            if (utf8Encoding.length < 1)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            TlsUtils.writeOpaque16(utf8Encoding, output);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    /**
     * Parse a {@link ServerName} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link ServerName} object.
     * @throws IOException
     */
    public static ServerName parse(InputStream input) throws IOException
    {
        short name_type = TlsUtils.readUint8(input);
        Object name;

        switch (name_type)
        {
        case NameType.host_name:
        {
            byte[] utf8Encoding = TlsUtils.readOpaque16(input);
            if (utf8Encoding.length < 1)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
            name = Strings.fromUTF8ByteArray(utf8Encoding);
            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return new ServerName(name_type, name);
    }

    protected static boolean isCorrectType(short nameType, Object name)
    {
        switch (nameType)
        {
        case NameType.host_name:
            return name instanceof String;
        default:
            throw new IllegalArgumentException("'name' is an unsupported value");
        }
    }
}
