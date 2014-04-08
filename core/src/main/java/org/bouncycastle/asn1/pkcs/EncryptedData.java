package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * The EncryptedData object.
 * <pre>
 *      EncryptedData ::= SEQUENCE {
 *           version Version,
 *           encryptedContentInfo EncryptedContentInfo
 *      }
 *
 *
 *      EncryptedContentInfo ::= SEQUENCE {
 *          contentType ContentType,
 *          contentEncryptionAlgorithm  ContentEncryptionAlgorithmIdentifier,
 *          encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
 *    }
 *
 *    EncryptedContent ::= OCTET STRING
 * </pre>
 */
public class EncryptedData
    extends ASN1Object
{
    ASN1Sequence                data;
    ASN1ObjectIdentifier bagId;
    ASN1Primitive bagValue;

    public static EncryptedData getInstance(
         Object  obj)
    {
         if (obj instanceof EncryptedData)
         {
             return (EncryptedData)obj;
         }

         if (obj != null)
         {
             return new EncryptedData(ASN1Sequence.getInstance(obj));
         }

         return null;
    }
     
    private EncryptedData(
        ASN1Sequence seq)
    {
        int version = ((ASN1Integer)seq.getObjectAt(0)).getValue().intValue();

        if (version != 0)
        {
            throw new IllegalArgumentException("sequence not version 0");
        }

        this.data = ASN1Sequence.getInstance(seq.getObjectAt(1));
    }

    public EncryptedData(
        ASN1ObjectIdentifier contentType,
        AlgorithmIdentifier     encryptionAlgorithm,
        ASN1Encodable content)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(contentType);
        v.add(encryptionAlgorithm.toASN1Primitive());
        v.add(new BERTaggedObject(false, 0, content));

        data = new BERSequence(v);
    }
        
    public ASN1ObjectIdentifier getContentType()
    {
        return ASN1ObjectIdentifier.getInstance(data.getObjectAt(0));
    }

    public AlgorithmIdentifier getEncryptionAlgorithm()
    {
        return AlgorithmIdentifier.getInstance(data.getObjectAt(1));
    }

    public ASN1OctetString getContent()
    {
        if (data.size() == 3)
        {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(data.getObjectAt(2));

            return ASN1OctetString.getInstance(o, false);
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(0));
        v.add(data);

        return new BERSequence(v);
    }
}
