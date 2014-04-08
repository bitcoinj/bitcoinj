package org.bouncycastle.crypto.tls;

/**
 * RFC 5764 4.1.1
 */
public class UseSRTPData
{
    private int[] protectionProfiles;
    private byte[] mki;

    /**
     * @param protectionProfiles see {@link SRTPProtectionProfile} for valid constants.
     * @param mki                valid lengths from 0 to 255.
     */
    public UseSRTPData(int[] protectionProfiles, byte[] mki)
    {
        if (protectionProfiles == null || protectionProfiles.length < 1
            || protectionProfiles.length >= (1 << 15))
        {
            throw new IllegalArgumentException(
                "'protectionProfiles' must have length from 1 to (2^15 - 1)");
        }

        if (mki == null)
        {
            mki = TlsUtils.EMPTY_BYTES;
        }
        else if (mki.length > 255)
        {
            throw new IllegalArgumentException("'mki' cannot be longer than 255 bytes");
        }

        this.protectionProfiles = protectionProfiles;
        this.mki = mki;
    }

    /**
     * @return see {@link SRTPProtectionProfile} for valid constants.
     */
    public int[] getProtectionProfiles()
    {
        return protectionProfiles;
    }

    /**
     * @return valid lengths from 0 to 255.
     */
    public byte[] getMki()
    {
        return mki;
    }
}
