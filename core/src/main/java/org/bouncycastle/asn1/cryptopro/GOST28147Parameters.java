package org.bouncycastle.asn1.cryptopro;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 algorithm identifier parameters for GOST-28147
 */
public class GOST28147Parameters
    extends ASN1Object
{
    private ASN1OctetString iv;
    private ASN1ObjectIdentifier paramSet;

    public static GOST28147Parameters getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GOST28147Parameters getInstance(
        Object obj)
    {
        if (obj instanceof GOST28147Parameters)
        {
            return (GOST28147Parameters)obj;
        }

        if (obj != null)
        {
            return new GOST28147Parameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * @deprecated use the getInstance() method. This constructor will vanish!
     */
    public GOST28147Parameters(
        ASN1Sequence  seq)
    {
        Enumeration     e = seq.getObjects();

        iv = (ASN1OctetString)e.nextElement();
        paramSet = (ASN1ObjectIdentifier)e.nextElement();
    }

    /**
     * <pre>
     * Gost28147-89-Parameters ::=
     *               SEQUENCE {
     *                       iv                   Gost28147-89-IV,
     *                       encryptionParamSet   OBJECT IDENTIFIER
     *                }
     *
     *   Gost28147-89-IV ::= OCTET STRING (SIZE (8))
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(iv);
        v.add(paramSet);

        return new DERSequence(v);
    }

    /**
     * Return the OID representing the sBox to use.
     *
     * @return the sBox OID.
     */
    public ASN1ObjectIdentifier getEncryptionParamSet()
    {
        return paramSet;
    }

    /**
     * Return the initialisation vector to use.
     *
     * @return the IV.
     */
    public byte[] getIV()
    {
        return iv.getOctets();
    }
}
