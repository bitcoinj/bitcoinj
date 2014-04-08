package org.bouncycastle.asn1.cmp;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class PKIStatus
    extends ASN1Object
{
    public static final int GRANTED                 = 0;
    public static final int GRANTED_WITH_MODS       = 1;
    public static final int REJECTION               = 2;
    public static final int WAITING                 = 3;
    public static final int REVOCATION_WARNING      = 4;
    public static final int REVOCATION_NOTIFICATION = 5;
    public static final int KEY_UPDATE_WARNING      = 6;

    public static final PKIStatus granted = new PKIStatus(GRANTED);
    public static final PKIStatus grantedWithMods = new PKIStatus(GRANTED_WITH_MODS);
    public static final PKIStatus rejection = new PKIStatus(REJECTION);
    public static final PKIStatus waiting = new PKIStatus(WAITING);
    public static final PKIStatus revocationWarning = new PKIStatus(REVOCATION_WARNING);
    public static final PKIStatus revocationNotification = new PKIStatus(REVOCATION_NOTIFICATION);
    public static final PKIStatus keyUpdateWaiting = new PKIStatus(KEY_UPDATE_WARNING);

    private ASN1Integer value;

    private PKIStatus(int value)
    {
        this(new ASN1Integer(value));
    }

    private PKIStatus(ASN1Integer value)
    {
        this.value = value;
    }

    public static PKIStatus getInstance(Object o)
    {
        if (o instanceof PKIStatus)
        {
            return (PKIStatus)o;
        }

        if (o != null)
        {
            return new PKIStatus(ASN1Integer.getInstance(o));
        }

        return null;
    }

    public BigInteger getValue()
    {
        return value.getValue();
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }
}
