package org.bouncycastle.asn1.x509;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

/**
 * The AuthorityKeyIdentifier object.
 * <pre>
 * id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 *
 *   AuthorityKeyIdentifier ::= SEQUENCE {
 *      keyIdentifier             [0] IMPLICIT KeyIdentifier           OPTIONAL,
 *      authorityCertIssuer       [1] IMPLICIT GeneralNames            OPTIONAL,
 *      authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber OPTIONAL  }
 *
 *   KeyIdentifier ::= OCTET STRING
 * </pre>
 *
 */
public class AuthorityKeyIdentifier
    extends ASN1Object
{
    ASN1OctetString keyidentifier=null;
    GeneralNames certissuer=null;
    ASN1Integer certserno=null;

    public static AuthorityKeyIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AuthorityKeyIdentifier getInstance(
        Object  obj)
    {
        if (obj instanceof AuthorityKeyIdentifier)
        {
            return (AuthorityKeyIdentifier)obj;
        }
        if (obj != null)
        {
            return new AuthorityKeyIdentifier(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static AuthorityKeyIdentifier fromExtensions(Extensions extensions)
    {
         return AuthorityKeyIdentifier.getInstance(extensions.getExtensionParsedValue(Extension.authorityKeyIdentifier));
    }

    protected AuthorityKeyIdentifier(
        ASN1Sequence   seq)
    {
        Enumeration     e = seq.getObjects();

        while (e.hasMoreElements())
        {
            ASN1TaggedObject o = DERTaggedObject.getInstance(e.nextElement());

            switch (o.getTagNo())
            {
            case 0:
                this.keyidentifier = ASN1OctetString.getInstance(o, false);
                break;
            case 1:
                this.certissuer = GeneralNames.getInstance(o, false);
                break;
            case 2:
                this.certserno = ASN1Integer.getInstance(o, false);
                break;
            default:
                throw new IllegalArgumentException("illegal tag");
            }
        }
    }

    /**
     *
     * Calulates the keyidentifier using a SHA1 hash over the BIT STRING
     * from SubjectPublicKeyInfo as defined in RFC2459.
     *
     * Example of making a AuthorityKeyIdentifier:
     * <pre>
     *   SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
     *       publicKey.getEncoded()).readObject());
     *   AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
     * </pre>
     *
     **/
    public AuthorityKeyIdentifier(
        SubjectPublicKeyInfo    spki)
    {
        Digest  digest = new SHA1Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];

        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        this.keyidentifier = new DEROctetString(resBuf);
    }

    /**
     * create an AuthorityKeyIdentifier with the GeneralNames tag and
     * the serial number provided as well.
     */
    public AuthorityKeyIdentifier(
        SubjectPublicKeyInfo    spki,
        GeneralNames            name,
        BigInteger              serialNumber)
    {
        Digest  digest = new SHA1Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];

        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);

        this.keyidentifier = new DEROctetString(resBuf);
        this.certissuer = GeneralNames.getInstance(name.toASN1Primitive());
        this.certserno = new ASN1Integer(serialNumber);
    }

    /**
     * create an AuthorityKeyIdentifier with the GeneralNames tag and
     * the serial number provided.
     */
    public AuthorityKeyIdentifier(
        GeneralNames            name,
        BigInteger              serialNumber)
    {
        this.keyidentifier = null;
        this.certissuer = GeneralNames.getInstance(name.toASN1Primitive());
        this.certserno = new ASN1Integer(serialNumber);
    }

    /**
      * create an AuthorityKeyIdentifier with a precomputed key identifier
      */
     public AuthorityKeyIdentifier(
         byte[]                  keyIdentifier)
     {
         this.keyidentifier = new DEROctetString(keyIdentifier);
         this.certissuer = null;
         this.certserno = null;
     }

    /**
     * create an AuthorityKeyIdentifier with a precomputed key identifier
     * and the GeneralNames tag and the serial number provided as well.
     */
    public AuthorityKeyIdentifier(
        byte[]                  keyIdentifier,
        GeneralNames            name,
        BigInteger              serialNumber)
    {
        this.keyidentifier = new DEROctetString(keyIdentifier);
        this.certissuer = GeneralNames.getInstance(name.toASN1Primitive());
        this.certserno = new ASN1Integer(serialNumber);
    }
    
    public byte[] getKeyIdentifier()
    {
        if (keyidentifier != null)
        {
            return keyidentifier.getOctets();
        }

        return null;
    }

    public GeneralNames getAuthorityCertIssuer()
    {
        return certissuer;
    }
    
    public BigInteger getAuthorityCertSerialNumber()
    {
        if (certserno != null)
        {
            return certserno.getValue();
        }
        
        return null;
    }
    
    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        if (keyidentifier != null)
        {
            v.add(new DERTaggedObject(false, 0, keyidentifier));
        }

        if (certissuer != null)
        {
            v.add(new DERTaggedObject(false, 1, certissuer));
        }

        if (certserno != null)
        {
            v.add(new DERTaggedObject(false, 2, certserno));
        }


        return new DERSequence(v);
    }

    public String toString()
    {
        return ("AuthorityKeyIdentifier: KeyID(" + this.keyidentifier.getOctets() + ")");
    }
}
