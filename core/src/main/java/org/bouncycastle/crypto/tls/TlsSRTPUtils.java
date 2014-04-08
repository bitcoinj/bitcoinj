package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Integers;

/**
 * RFC 5764 DTLS Extension to Establish Keys for SRTP.
 */
public class TlsSRTPUtils
{
    public static final Integer EXT_use_srtp = Integers.valueOf(ExtensionType.use_srtp);

    public static void addUseSRTPExtension(Hashtable extensions, UseSRTPData useSRTPData)
        throws IOException
    {
        extensions.put(EXT_use_srtp, createUseSRTPExtension(useSRTPData));
    }

    public static UseSRTPData getUseSRTPExtension(Hashtable extensions)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_use_srtp);
        return extensionData == null ? null : readUseSRTPExtension(extensionData);
    }

    public static byte[] createUseSRTPExtension(UseSRTPData useSRTPData)
        throws IOException
    {
        if (useSRTPData == null)
        {
            throw new IllegalArgumentException("'useSRTPData' cannot be null");
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // SRTPProtectionProfiles
        TlsUtils.writeUint16ArrayWithUint16Length(useSRTPData.getProtectionProfiles(), buf);

        // srtp_mki
        TlsUtils.writeOpaque8(useSRTPData.getMki(), buf);

        return buf.toByteArray();
    }

    public static UseSRTPData readUseSRTPExtension(byte[] extensionData)
        throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        // SRTPProtectionProfiles
        int length = TlsUtils.readUint16(buf);
        if (length < 2 || (length & 1) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        int[] protectionProfiles = TlsUtils.readUint16Array(length / 2, buf);

        // srtp_mki
        byte[] mki = TlsUtils.readOpaque8(buf);

        TlsProtocol.assertEmpty(buf);

        return new UseSRTPData(protectionProfiles, mki);
    }
}
