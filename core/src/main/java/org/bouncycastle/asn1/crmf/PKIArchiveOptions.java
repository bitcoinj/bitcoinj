package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

public class PKIArchiveOptions
    extends ASN1Object
    implements ASN1Choice
{
    public static final int encryptedPrivKey = 0;
    public static final int keyGenParameters = 1;
    public static final int archiveRemGenPrivKey = 2;

    private ASN1Encodable value;

    public static PKIArchiveOptions getInstance(Object o)
    {
        if (o == null || o instanceof PKIArchiveOptions)
        {
            return (PKIArchiveOptions)o;
        }
        else if (o instanceof ASN1TaggedObject)
        {
            return new PKIArchiveOptions((ASN1TaggedObject)o);
        }

        throw new IllegalArgumentException("unknown object: " + o);
    }

    private PKIArchiveOptions(ASN1TaggedObject tagged)
    {
        switch (tagged.getTagNo())
        {
        case encryptedPrivKey:
            value = EncryptedKey.getInstance(tagged.getObject());
            break;
        case keyGenParameters:
            value = ASN1OctetString.getInstance(tagged, false);
            break;
        case archiveRemGenPrivKey:
            value = ASN1Boolean.getInstance(tagged, false);
            break;
        default:
            throw new IllegalArgumentException("unknown tag number: " + tagged.getTagNo());
        }
    }

    public PKIArchiveOptions(EncryptedKey encKey)
    {
        this.value = encKey;
    }

    public PKIArchiveOptions(ASN1OctetString keyGenParameters)
    {
        this.value = keyGenParameters;
    }

    public PKIArchiveOptions(boolean archiveRemGenPrivKey)
    {
        this.value = ASN1Boolean.getInstance(archiveRemGenPrivKey);
    }

    public int getType()
    {
        if (value instanceof EncryptedKey)
        {
            return encryptedPrivKey;
        }

        if (value instanceof ASN1OctetString)
        {
            return keyGenParameters;
        }

        return archiveRemGenPrivKey;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }
    
    /**
     * <pre>
     *  PKIArchiveOptions ::= CHOICE {
     *      encryptedPrivKey     [0] EncryptedKey,
     *      -- the actual value of the private key
     *      keyGenParameters     [1] KeyGenParameters,
     *      -- parameters which allow the private key to be re-generated
     *      archiveRemGenPrivKey [2] BOOLEAN }
     *      -- set to TRUE if sender wishes receiver to archive the private
     *      -- key of a key pair that the receiver generates in response to
     *      -- this request; set to FALSE if no archival is desired.
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (value instanceof EncryptedKey)
        {
            return new DERTaggedObject(true, encryptedPrivKey, value);  // choice
        }

        if (value instanceof ASN1OctetString)
        {
            return new DERTaggedObject(false, keyGenParameters, value);
        }

        return new DERTaggedObject(false, archiveRemGenPrivKey, value);
    }
}
