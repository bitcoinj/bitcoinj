package com.google.bitcoin.bouncycastle.asn1.x509.qualified;

import java.util.Enumeration;

import com.google.bitcoin.bouncycastle.asn1.ASN1Encodable;
import com.google.bitcoin.bouncycastle.asn1.ASN1EncodableVector;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERObjectIdentifier;
import com.google.bitcoin.bouncycastle.asn1.DERSequence;
import com.google.bitcoin.bouncycastle.asn1.x509.GeneralName;

/**
 * The SemanticsInformation object.
 * <pre>
 *       SemanticsInformation ::= SEQUENCE {
 *         semanticsIdentifier        OBJECT IDENTIFIER   OPTIONAL,
 *         nameRegistrationAuthorities NameRegistrationAuthorities
 *                                                         OPTIONAL }
 *         (WITH COMPONENTS {..., semanticsIdentifier PRESENT}|
 *          WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
 *
 *     NameRegistrationAuthorities ::=  SEQUENCE SIZE (1..MAX) OF
 *         GeneralName
 * </pre>
 */
public class SemanticsInformation extends ASN1Encodable
{
    DERObjectIdentifier semanticsIdentifier;
    GeneralName[] nameRegistrationAuthorities;    
    
    public static SemanticsInformation getInstance(Object obj)
    {
        if (obj == null || obj instanceof SemanticsInformation)
        {
            return (SemanticsInformation)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new SemanticsInformation(ASN1Sequence.getInstance(obj));            
        }
        
        throw new IllegalArgumentException("unknown object in getInstance");
    }
        
    public SemanticsInformation(ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();
        if (seq.size() < 1)
        {
             throw new IllegalArgumentException("no objects in SemanticsInformation");
        }
        
        Object object = e.nextElement();
        if (object instanceof DERObjectIdentifier)
        {
            semanticsIdentifier = DERObjectIdentifier.getInstance(object);
            if (e.hasMoreElements())
            {
                object = e.nextElement();
            }
            else
            {
                object = null;
            }
        }
        
        if (object != null)
        {
            ASN1Sequence generalNameSeq = ASN1Sequence.getInstance(object);
            nameRegistrationAuthorities = new GeneralName[generalNameSeq.size()];
            for (int i= 0; i < generalNameSeq.size(); i++)
            {
                nameRegistrationAuthorities[i] = GeneralName.getInstance(generalNameSeq.getObjectAt(i));
            } 
        }
    }
        
    public SemanticsInformation(
        DERObjectIdentifier semanticsIdentifier,
        GeneralName[] generalNames)
    {
        this.semanticsIdentifier = semanticsIdentifier;
        this.nameRegistrationAuthorities = generalNames;
    }

    public SemanticsInformation(DERObjectIdentifier semanticsIdentifier)
    {
        this.semanticsIdentifier = semanticsIdentifier;
        this.nameRegistrationAuthorities = null;
    }

    public SemanticsInformation(GeneralName[] generalNames)
    {
        this.semanticsIdentifier = null;
        this.nameRegistrationAuthorities = generalNames;
    }        
    
    public DERObjectIdentifier getSemanticsIdentifier()
    {
        return semanticsIdentifier;
    }
        
    public GeneralName[] getNameRegistrationAuthorities()
    {
        return nameRegistrationAuthorities;
    } 
    
    public DERObject toASN1Object() 
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        
        if (this.semanticsIdentifier != null)
        {
            seq.add(semanticsIdentifier);
        }
        if (this.nameRegistrationAuthorities != null)
        {
            ASN1EncodableVector seqname = new ASN1EncodableVector();
            for (int i = 0; i < nameRegistrationAuthorities.length; i++) 
            {
                seqname.add(nameRegistrationAuthorities[i]);
            }            
            seq.add(new DERSequence(seqname));
        }            
        
        return new DERSequence(seq);
    }                   
}
