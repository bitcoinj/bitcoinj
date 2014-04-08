package org.bouncycastle.asn1.pkcs;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class PrivateKeyInfo
    extends ASN1Object
{
    private ASN1OctetString         privKey;
    private AlgorithmIdentifier     algId;
    private ASN1Set                 attributes;

    public static PrivateKeyInfo getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PrivateKeyInfo getInstance(
        Object  obj)
    {
        if (obj instanceof PrivateKeyInfo)
        {
            return (PrivateKeyInfo)obj;
        }
        else if (obj != null)
        {
            return new PrivateKeyInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }
        
    public PrivateKeyInfo(
        AlgorithmIdentifier algId,
        ASN1Encodable       privateKey)
        throws IOException
    {
        this(algId, privateKey, null);
    }

    public PrivateKeyInfo(
        AlgorithmIdentifier algId,
        ASN1Encodable       privateKey,
        ASN1Set             attributes)
        throws IOException
    {
        this.privKey = new DEROctetString(privateKey.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        this.algId = algId;
        this.attributes = attributes;
    }

    /**
     * @deprecated use PrivateKeyInfo.getInstance()
     * @param seq
     */
    public PrivateKeyInfo(
        ASN1Sequence  seq)
    {
        Enumeration e = seq.getObjects();

        BigInteger  version = ((ASN1Integer)e.nextElement()).getValue();
        if (version.intValue() != 0)
        {
            throw new IllegalArgumentException("wrong version for private key info");
        }

        algId = AlgorithmIdentifier.getInstance(e.nextElement());
        privKey = ASN1OctetString.getInstance(e.nextElement());
        
        if (e.hasMoreElements())
        {
           attributes = ASN1Set.getInstance((ASN1TaggedObject)e.nextElement(), false);
        }
    }

    public AlgorithmIdentifier getPrivateKeyAlgorithm()
    {
        return algId;
    }
        /**
          * @deprecated use getPrivateKeyAlgorithm()
     */
    public AlgorithmIdentifier getAlgorithmId()
    {
        return algId;
    }

    public ASN1Encodable parsePrivateKey()
        throws IOException
    {
        return ASN1Primitive.fromByteArray(privKey.getOctets());
    }

    /**
          * @deprecated use parsePrivateKey()
     */
    public ASN1Primitive getPrivateKey()
    {
        try
        {
            return parsePrivateKey().toASN1Primitive();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to parse private key");
        }
    }
    
    public ASN1Set getAttributes()
    {
        return attributes;
    }

    /**
     * write out an RSA private key with its associated information
     * as described in PKCS8.
     * <pre>
     *      PrivateKeyInfo ::= SEQUENCE {
     *                              version Version,
     *                              privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
     *                              privateKey PrivateKey,
     *                              attributes [0] IMPLICIT Attributes OPTIONAL 
     *                          }
     *      Version ::= INTEGER {v1(0)} (v1,...)
     *
     *      PrivateKey ::= OCTET STRING
     *
     *      Attributes ::= SET OF Attribute
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(0));
        v.add(algId);
        v.add(privKey);

        if (attributes != null)
        {
            v.add(new DERTaggedObject(false, 0, attributes));
        }
        
        return new DERSequence(v);
    }
}
