package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;

/**
 * Policy qualifiers, used in the X509V3 CertificatePolicies
 * extension.
 * 
 * <pre>
 *   PolicyQualifierInfo ::= SEQUENCE {
 *       policyQualifierId  PolicyQualifierId,
 *       qualifier          ANY DEFINED BY policyQualifierId }
 * </pre>
 */
public class PolicyQualifierInfo
    extends ASN1Object
{
   private ASN1ObjectIdentifier policyQualifierId;
   private ASN1Encodable        qualifier;

   /**
    * Creates a new <code>PolicyQualifierInfo</code> instance.
    *
    * @param policyQualifierId a <code>PolicyQualifierId</code> value
    * @param qualifier the qualifier, defined by the above field.
    */
   public PolicyQualifierInfo(
       ASN1ObjectIdentifier policyQualifierId,
       ASN1Encodable qualifier) 
   {
      this.policyQualifierId = policyQualifierId;
      this.qualifier = qualifier;
   }

   /**
    * Creates a new <code>PolicyQualifierInfo</code> containing a
    * cPSuri qualifier.
    *
    * @param cps the CPS (certification practice statement) uri as a
    * <code>String</code>.
    */
   public PolicyQualifierInfo(
       String cps) 
   {
      policyQualifierId = PolicyQualifierId.id_qt_cps;
      qualifier = new DERIA5String (cps);
   }

   /**
    * Creates a new <code>PolicyQualifierInfo</code> instance.
    *
    * @param as <code>PolicyQualifierInfo</code> X509 structure
    * encoded as an ASN1Sequence.
    * @deprecated use PolicyQualifierInfo.getInstance()
    */
   public PolicyQualifierInfo(
       ASN1Sequence as)
   {
        if (as.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + as.size());
        }

        policyQualifierId = ASN1ObjectIdentifier.getInstance(as.getObjectAt(0));
        qualifier = as.getObjectAt(1);
   }

   public static PolicyQualifierInfo getInstance(
       Object obj)
   {
        if (obj instanceof PolicyQualifierInfo)
        {
            return (PolicyQualifierInfo)obj;
        }
        else if (obj != null)
        {
            return new PolicyQualifierInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
   }


   public ASN1ObjectIdentifier getPolicyQualifierId()
   {
       return policyQualifierId;
   }

   public ASN1Encodable getQualifier()
   {
       return qualifier;
   }
   
   /**
    * Returns a DER-encodable representation of this instance. 
    *
    * @return a <code>ASN1Primitive</code> value
    */
   public ASN1Primitive toASN1Primitive()
   {
      ASN1EncodableVector dev = new ASN1EncodableVector();
      dev.add(policyQualifierId);
      dev.add(qualifier);

      return new DERSequence(dev);
   }
}
