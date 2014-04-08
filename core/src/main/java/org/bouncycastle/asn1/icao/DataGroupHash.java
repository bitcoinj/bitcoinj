package org.bouncycastle.asn1.icao;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * The DataGroupHash object.
 * <pre>
 * DataGroupHash  ::=  SEQUENCE {
 *      dataGroupNumber         DataGroupNumber,
 *      dataGroupHashValue     OCTET STRING }
 * 
 * DataGroupNumber ::= INTEGER {
 *         dataGroup1    (1),
 *         dataGroup1    (2),
 *         dataGroup1    (3),
 *         dataGroup1    (4),
 *         dataGroup1    (5),
 *         dataGroup1    (6),
 *         dataGroup1    (7),
 *         dataGroup1    (8),
 *         dataGroup1    (9),
 *         dataGroup1    (10),
 *         dataGroup1    (11),
 *         dataGroup1    (12),
 *         dataGroup1    (13),
 *         dataGroup1    (14),
 *         dataGroup1    (15),
 *         dataGroup1    (16) }
 * 
 * </pre>
 */
public class DataGroupHash 
    extends ASN1Object
{
    ASN1Integer dataGroupNumber;    
    ASN1OctetString    dataGroupHashValue;
    
    public static DataGroupHash getInstance(
        Object obj)
    {
        if (obj instanceof DataGroupHash)
        {
            return (DataGroupHash)obj;
        }
        else if (obj != null)
        {
            return new DataGroupHash(ASN1Sequence.getInstance(obj));
        }

        return null;
    }                
            
    private DataGroupHash(ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();

        // dataGroupNumber
        dataGroupNumber = ASN1Integer.getInstance(e.nextElement());
        // dataGroupHashValue
        dataGroupHashValue = ASN1OctetString.getInstance(e.nextElement());   
    }
    
    public DataGroupHash(
        int dataGroupNumber,        
        ASN1OctetString     dataGroupHashValue)
    {
        this.dataGroupNumber = new ASN1Integer(dataGroupNumber);
        this.dataGroupHashValue = dataGroupHashValue; 
    }    

    public int getDataGroupNumber()
    {
        return dataGroupNumber.getValue().intValue();
    }
    
    public ASN1OctetString getDataGroupHashValue()
    {
        return dataGroupHashValue;
    }     
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(dataGroupNumber);
        seq.add(dataGroupHashValue);  

        return new DERSequence(seq);
    }
}
