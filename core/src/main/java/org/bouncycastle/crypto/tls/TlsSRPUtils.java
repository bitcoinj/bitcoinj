package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Integers;

public class TlsSRPUtils
{
    public static final Integer EXT_SRP = Integers.valueOf(ExtensionType.srp);

    public static void addSRPExtension(Hashtable extensions, byte[] identity) throws IOException
    {
        extensions.put(EXT_SRP, createSRPExtension(identity));
    }

    public static byte[] getSRPExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_SRP);
        return extensionData == null ? null : readSRPExtension(extensionData);
    }

    public static byte[] createSRPExtension(byte[] identity) throws IOException
    {
        if (identity == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return TlsUtils.encodeOpaque8(identity);
    }

    public static byte[] readSRPExtension(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);
        byte[] identity = TlsUtils.readOpaque8(buf);

        TlsProtocol.assertEmpty(buf);

        return identity;
    }
}
