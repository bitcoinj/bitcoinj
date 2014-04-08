package org.bouncycastle.bcpg.sig;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Strings;

/**
 * Class provided a NotationData object according to
 * RFC2440, Chapter 5.2.3.15. Notation Data
 */
public class NotationData
    extends SignatureSubpacket
{
    public static final int HEADER_FLAG_LENGTH = 4;
    public static final int HEADER_NAME_LENGTH = 2;
    public static final int HEADER_VALUE_LENGTH = 2;

    public NotationData(boolean critical, byte[] data)
    {
        super(SignatureSubpacketTags.NOTATION_DATA, critical, data);
    }

    public NotationData(
        boolean critical,
        boolean humanReadable,
        String notationName,
        String notationValue)
    {
        super(SignatureSubpacketTags.NOTATION_DATA, critical, createData(humanReadable, notationName, notationValue));
    }

    private static byte[] createData(boolean humanReadable, String notationName, String notationValue)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

//        (4 octets of flags, 2 octets of name length (M),
//        2 octets of value length (N),
//        M octets of name data,
//        N octets of value data)

        // flags
        out.write(humanReadable ? 0x80 : 0x00);
        out.write(0x0);
        out.write(0x0);
        out.write(0x0);

        byte[] nameData, valueData = null;
        int nameLength, valueLength;

        nameData = Strings.toUTF8ByteArray(notationName);
        nameLength = Math.min(nameData.length, 0xFFFF);

        if (nameLength != nameData.length)
        {
            throw new IllegalArgumentException("notationName exceeds maximum length.");
        }

        valueData = Strings.toUTF8ByteArray(notationValue);
        valueLength = Math.min(valueData.length, 0xFFFF);
        if (valueLength != valueData.length)
        {
            throw new IllegalArgumentException("notationValue exceeds maximum length.");
        }

        // name length
        out.write((nameLength >>> 8) & 0xFF);
        out.write((nameLength >>> 0) & 0xFF);

        // value length
        out.write((valueLength >>> 8) & 0xFF);
        out.write((valueLength >>> 0) & 0xFF);

        // name
        out.write(nameData, 0, nameLength);

        // value
        out.write(valueData, 0, valueLength);

        return out.toByteArray();
    }

    public boolean isHumanReadable()
    {
        return data[0] == (byte)0x80;
    }

    public String getNotationName()
    {
        int nameLength = (((data[HEADER_FLAG_LENGTH] & 0xff) << 8) + (data[HEADER_FLAG_LENGTH + 1] & 0xff));

        byte bName[] = new byte[nameLength];
        System.arraycopy(data, HEADER_FLAG_LENGTH + HEADER_NAME_LENGTH + HEADER_VALUE_LENGTH, bName, 0, nameLength);

        return Strings.fromUTF8ByteArray(bName);
    }

    public String getNotationValue()
    {
        return Strings.fromUTF8ByteArray(getNotationValueBytes());
    }

    public byte[] getNotationValueBytes()
    {
        int nameLength = (((data[HEADER_FLAG_LENGTH] & 0xff) << 8) + (data[HEADER_FLAG_LENGTH + 1] & 0xff));
        int valueLength = (((data[HEADER_FLAG_LENGTH + HEADER_NAME_LENGTH] & 0xff) << 8) + (data[HEADER_FLAG_LENGTH + HEADER_NAME_LENGTH + 1] & 0xff));

        byte bValue[] = new byte[valueLength];
        System.arraycopy(data, HEADER_FLAG_LENGTH + HEADER_NAME_LENGTH + HEADER_VALUE_LENGTH + nameLength, bValue, 0, valueLength);
        return bValue;
    }
}
