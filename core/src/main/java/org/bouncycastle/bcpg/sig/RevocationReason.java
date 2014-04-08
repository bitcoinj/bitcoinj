package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Strings;

/**
 * Represents revocation reason OpenPGP signature sub packet.
 */
public class RevocationReason extends SignatureSubpacket
{
    public RevocationReason(boolean isCritical, byte[] data)
    {
        super(SignatureSubpacketTags.REVOCATION_REASON, isCritical, data);
    }

    public RevocationReason(boolean isCritical, byte reason, String description)
    {
        super(SignatureSubpacketTags.REVOCATION_REASON, isCritical, createData(reason, description));
    }

    private static byte[] createData(byte reason, String description)
    {
        byte[] descriptionBytes = Strings.toUTF8ByteArray(description);
        byte[] data = new byte[1 + descriptionBytes.length];

        data[0] = reason;
        System.arraycopy(descriptionBytes, 0, data, 1, descriptionBytes.length);

        return data;
    }

    public byte getRevocationReason()
    {
        return getData()[0];
    }

    public String getRevocationDescription()
    {
        byte[] data = getData();
        if (data.length == 1)
        {
            return "";
        }

        byte[] description = new byte[data.length - 1];
        System.arraycopy(data, 1, description, 0, description.length);

        return Strings.fromUTF8ByteArray(description);
    }
}
