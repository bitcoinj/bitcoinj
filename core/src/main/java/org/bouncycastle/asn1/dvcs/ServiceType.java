package org.bouncycastle.asn1.dvcs;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;


/**
 * ServiceType ::= ENUMERATED { cpd(1), vsd(2), cpkc(3), ccpd(4) }
 */

public class ServiceType
    extends ASN1Object
{
    /**
     * Identifier of CPD service (Certify Possession of Data).
     */
    public static final ServiceType CPD = new ServiceType(1);

    /**
     * Identifier of VSD service (Verify Signed Document).
     */
    public static final ServiceType VSD = new ServiceType(2);

    /**
     * Identifier of VPKC service (Verify Public Key Certificates (also referred to as CPKC)).
     */
    public static final ServiceType VPKC = new ServiceType(3);

    /**
     * Identifier of CCPD service (Certify Claim of Possession of Data).
     */
    public static final ServiceType CCPD = new ServiceType(4);

    private ASN1Enumerated value;

    public ServiceType(int value)
    {
        this.value = new ASN1Enumerated(value);
    }

    private ServiceType(ASN1Enumerated value)
    {
        this.value = value;
    }

    public static ServiceType getInstance(Object obj)
    {
        if (obj instanceof ServiceType)
        {
            return (ServiceType)obj;
        }
        else if (obj != null)
        {
            return new ServiceType(ASN1Enumerated.getInstance(obj));
        }

        return null;
    }

    public static ServiceType getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Enumerated.getInstance(obj, explicit));
    }

    public BigInteger getValue()
    {
        return value.getValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }

    public String toString()
    {
        int num = value.getValue().intValue();
        return "" + num + (
            num == CPD.getValue().intValue() ? "(CPD)" :
                num == VSD.getValue().intValue() ? "(VSD)" :
                    num == VPKC.getValue().intValue() ? "(VPKC)" :
                        num == CCPD.getValue().intValue() ? "(CCPD)" :
                            "?");
    }

}
