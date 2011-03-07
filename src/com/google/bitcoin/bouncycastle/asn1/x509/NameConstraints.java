package com.google.bitcoin.bouncycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.ASN1TaggedObject;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.DERTaggedObject;

public class NameConstraints
    extends ASN1Encodable
{
    private ASN1Sequence permitted, excluded;

    public NameConstraints(ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements())
        {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            switch (o.getTagNo())
            {
            case 0:
                permitted = ASN1Sequence.getInstance(o, false);
                break;
            case 1:
                excluded = ASN1Sequence.getInstance(o, false);
                break;
            }
        }
    }

    /**
     * Constructor from a given details.
     * 
     * <p>
     * permitted and excluded are Vectors of GeneralSubtree objects.
     * 
     * @param permitted
     *            Permitted subtrees
     * @param excluded
     *            Excludes subtrees
     */
    public NameConstraints(
        Vector permitted,
        Vector excluded)
    {
        if (permitted != null)
        {
            this.permitted = createSequence(permitted);
        }
        if (excluded != null)
        {
            this.excluded = createSequence(excluded);
        }
    }

    private DERSequence createSequence(Vector subtree)
    {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        Enumeration e = subtree.elements(); 
        while (e.hasMoreElements())
        {
            vec.add((GeneralSubtree)e.nextElement());
        }
        
        return new DERSequence(vec);
    }

    public ASN1Sequence getPermittedSubtrees() 
    {
        return permitted;
    }

    public ASN1Sequence getExcludedSubtrees() 
    {
        return excluded;
    }

    /*
     * NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
     * OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }
     */
    public DERObject toASN1Object() 
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (permitted != null) 
        {
            v.add(new DERTaggedObject(false, 0, permitted));
        }

        if (excluded != null) 
        {
            v.add(new DERTaggedObject(false, 1, excluded));
        }

        return new DERSequence(v);
    }
}
