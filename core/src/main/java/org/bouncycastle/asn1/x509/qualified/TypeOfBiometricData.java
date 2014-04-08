package org.bouncycastle.asn1.x509.qualified;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * The TypeOfBiometricData object.
 * <pre>
 * TypeOfBiometricData ::= CHOICE {
 *   predefinedBiometricType   PredefinedBiometricType,
 *   biometricDataOid          OBJECT IDENTIFIER }
 *
 * PredefinedBiometricType ::= INTEGER {
 *   picture(0),handwritten-signature(1)}
 *   (picture|handwritten-signature)
 * </pre>
 */
public class TypeOfBiometricData  
    extends ASN1Object
    implements ASN1Choice
{
    public static final int PICTURE                     = 0;
    public static final int HANDWRITTEN_SIGNATURE       = 1;

    ASN1Encodable      obj;

    public static TypeOfBiometricData getInstance(Object obj)
    {
        if (obj == null || obj instanceof TypeOfBiometricData)
        {
            return (TypeOfBiometricData)obj;
        }

        if (obj instanceof ASN1Integer)
        {
            ASN1Integer predefinedBiometricTypeObj = ASN1Integer.getInstance(obj);
            int  predefinedBiometricType = predefinedBiometricTypeObj.getValue().intValue();

            return new TypeOfBiometricData(predefinedBiometricType);
        }
        else if (obj instanceof ASN1ObjectIdentifier)
        {
            ASN1ObjectIdentifier BiometricDataID = ASN1ObjectIdentifier.getInstance(obj);
            return new TypeOfBiometricData(BiometricDataID);
        }

        throw new IllegalArgumentException("unknown object in getInstance");
    }
        
    public TypeOfBiometricData(int predefinedBiometricType)
    {
        if (predefinedBiometricType == PICTURE || predefinedBiometricType == HANDWRITTEN_SIGNATURE)
        {
                obj = new ASN1Integer(predefinedBiometricType);
        }
        else
        {
            throw new IllegalArgumentException("unknow PredefinedBiometricType : " + predefinedBiometricType);
        }        
    }
    
    public TypeOfBiometricData(ASN1ObjectIdentifier BiometricDataID)
    {
        obj = BiometricDataID;
    }
    
    public boolean isPredefined()
    {
        return obj instanceof ASN1Integer;
    }
    
    public int getPredefinedBiometricType()
    {
        return ((ASN1Integer)obj).getValue().intValue();
    }
    
    public ASN1ObjectIdentifier getBiometricDataOid()
    {
        return (ASN1ObjectIdentifier)obj;
    }
    
    public ASN1Primitive toASN1Primitive()
    {        
        return obj.toASN1Primitive();
    }
}
