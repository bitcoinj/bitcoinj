package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

public class Features
    extends SignatureSubpacket
{

    /** Identifier for the modification detection feature */
    public static final byte FEATURE_MODIFICATION_DETECTION = 1;

    private static final byte[] featureToByteArray(byte feature)
    {
        byte[] data = new byte[1];
        data[0] = feature;
        return data;
    }

    public Features(boolean critical, byte[] data)
    {
        super(SignatureSubpacketTags.FEATURES, critical, data);
    }

    public Features(boolean critical, byte feature)
    {
        super(SignatureSubpacketTags.FEATURES, critical, featureToByteArray(feature));
    }

    /**
     * Returns if modification detection is supported.
     */
    public boolean supportsModificationDetection()
    {
        return supportsFeature(FEATURE_MODIFICATION_DETECTION);
    }


//    /**  Class should be immutable.
//     * Set modification detection support.
//     */
//    public void setSupportsModificationDetection(boolean support)
//    {
//        setSupportsFeature(FEATURE_MODIFICATION_DETECTION, support);
//    }


    /**
     * Returns if a particular feature is supported.
     */
    public boolean supportsFeature(byte feature)
    {
        for (int i = 0; i < data.length; i++)
        {
            if (data[i] == feature)
            {
                return true;
            }
        }
        return false;
    }


    /**
     * Sets support for a particular feature.
     */
    private void setSupportsFeature(byte feature, boolean support)
    {
        if (feature == 0)
        {
            throw new IllegalArgumentException("feature == 0");
        }
        if (supportsFeature(feature) != support)
        {
            if (support == true)
            {
                byte[] temp = new byte[data.length + 1];
                System.arraycopy(data, 0, temp, 0, data.length);
                temp[data.length] = feature;
                data = temp;
            }
            else
            {
                for (int i = 0; i < data.length; i++)
                {
                    if (data[i] == feature)
                    {
                        byte[] temp = new byte[data.length - 1];
                        System.arraycopy(data, 0, temp, 0, i);
                        System.arraycopy(data, i + 1, temp, i, temp.length - i);
                        data = temp;
                        break;
                    }
                }
            }
        }
    }
}
