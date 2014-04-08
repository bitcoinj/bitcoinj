package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;

/**
 * This class implements an ASN.1 encoded Rainbow public key. The ASN.1 definition
 * of this structure is:
 * <pre>
 *       RainbowPublicKey ::= SEQUENCE {
 *         CHOICE
 *         {
 *         oid        OBJECT IDENTIFIER         -- OID identifying the algorithm
 *         version    INTEGER                    -- 0
 *         }
 *         docLength        Integer               -- length of the code
 *         coeffquadratic   SEQUENCE OF OCTET STRING -- quadratic (mixed) coefficients
 *         coeffsingular    SEQUENCE OF OCTET STRING -- singular coefficients
 *         coeffscalar    SEQUENCE OF OCTET STRING -- scalar coefficients
 *       }
 * </pre>
 */
public class RainbowPublicKey
    extends ASN1Object
{
    private ASN1Integer version;
    private ASN1ObjectIdentifier oid;
    private ASN1Integer docLength;
    private byte[][] coeffQuadratic;
    private byte[][] coeffSingular;
    private byte[] coeffScalar;

    private RainbowPublicKey(ASN1Sequence seq)
    {
        // <oidString>  or version
        if (seq.getObjectAt(0) instanceof ASN1Integer)
        {
            version = ASN1Integer.getInstance(seq.getObjectAt(0));
        }
        else
        {
            oid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        }

        docLength = ASN1Integer.getInstance(seq.getObjectAt(1));

        ASN1Sequence asnCoeffQuad = ASN1Sequence.getInstance(seq.getObjectAt(2));
        coeffQuadratic = new byte[asnCoeffQuad.size()][];
        for (int quadSize = 0; quadSize < asnCoeffQuad.size(); quadSize++)
        {
            coeffQuadratic[quadSize] = ASN1OctetString.getInstance(asnCoeffQuad.getObjectAt(quadSize)).getOctets();
        }

        ASN1Sequence asnCoeffSing = (ASN1Sequence)seq.getObjectAt(3);
        coeffSingular = new byte[asnCoeffSing.size()][];
        for (int singSize = 0; singSize < asnCoeffSing.size(); singSize++)
        {
            coeffSingular[singSize] = ASN1OctetString.getInstance(asnCoeffSing.getObjectAt(singSize)).getOctets();
        }

        ASN1Sequence asnCoeffScalar = (ASN1Sequence)seq.getObjectAt(4);
        coeffScalar = ASN1OctetString.getInstance(asnCoeffScalar.getObjectAt(0)).getOctets();
    }

    public RainbowPublicKey(int docLength, short[][] coeffQuadratic, short[][] coeffSingular, short[] coeffScalar)
    {
        this.version = new ASN1Integer(0);
        this.docLength = new ASN1Integer(docLength);
        this.coeffQuadratic = RainbowUtil.convertArray(coeffQuadratic);
        this.coeffSingular = RainbowUtil.convertArray(coeffSingular);
        this.coeffScalar = RainbowUtil.convertArray(coeffScalar);
    }

    public static RainbowPublicKey getInstance(Object o)
    {
        if (o instanceof RainbowPublicKey)
        {
            return (RainbowPublicKey)o;
        }
        else if (o != null)
        {
            return new RainbowPublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    /**
     * @return the docLength
     */
    public int getDocLength()
    {
        return this.docLength.getValue().intValue();
    }

    /**
     * @return the coeffquadratic
     */
    public short[][] getCoeffQuadratic()
    {
        return RainbowUtil.convertArray(coeffQuadratic);
    }

    /**
     * @return the coeffsingular
     */
    public short[][] getCoeffSingular()
    {
        return RainbowUtil.convertArray(coeffSingular);
    }

    /**
     * @return the coeffscalar
     */
    public short[] getCoeffScalar()
    {
        return RainbowUtil.convertArray(coeffScalar);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        // encode <oidString>  or version
        if (version != null)
        {
            v.add(version);
        }
        else
        {
            v.add(oid);
        }

        // encode <docLength>
        v.add(docLength);

        // encode <coeffQuadratic>
        ASN1EncodableVector asnCoeffQuad = new ASN1EncodableVector();
        for (int i = 0; i < coeffQuadratic.length; i++)
        {
            asnCoeffQuad.add(new DEROctetString(coeffQuadratic[i]));
        }
        v.add(new DERSequence(asnCoeffQuad));

        // encode <coeffSingular>
        ASN1EncodableVector asnCoeffSing = new ASN1EncodableVector();
        for (int i = 0; i < coeffSingular.length; i++)
        {
            asnCoeffSing.add(new DEROctetString(coeffSingular[i]));
        }
        v.add(new DERSequence(asnCoeffSing));

        // encode <coeffScalar>
        ASN1EncodableVector asnCoeffScalar = new ASN1EncodableVector();
        asnCoeffScalar.add(new DEROctetString(coeffScalar));
        v.add(new DERSequence(asnCoeffScalar));


        return new DERSequence(v);
    }
}
