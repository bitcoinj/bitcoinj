package org.bouncycastle.asn1.x509.qualified;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * The MonetaryValue object.
 * <pre>
 * MonetaryValue  ::=  SEQUENCE {
 *       currency              Iso4217CurrencyCode,
 *       amount               INTEGER, 
 *       exponent             INTEGER }
 * -- value = amount * 10^exponent
 * </pre>
 */
public class MonetaryValue 
    extends ASN1Object
{
    private Iso4217CurrencyCode currency;
    private ASN1Integer         amount;
    private ASN1Integer         exponent;
        
    public static MonetaryValue getInstance(
        Object obj)
    {
        if (obj instanceof MonetaryValue)
        {
            return (MonetaryValue)obj;
        }

        if (obj != null)
        {
            return new MonetaryValue(ASN1Sequence.getInstance(obj));            
        }
        
        return null;
    }
        
    private MonetaryValue(
        ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();    
        // currency
        currency = Iso4217CurrencyCode.getInstance(e.nextElement());
        // hashAlgorithm
        amount = ASN1Integer.getInstance(e.nextElement());
        // exponent
        exponent = ASN1Integer.getInstance(e.nextElement());            
    }
        
    public MonetaryValue(
        Iso4217CurrencyCode currency, 
        int                 amount, 
        int                 exponent)
    {    
        this.currency = currency;
        this.amount = new ASN1Integer(amount);
        this.exponent = new ASN1Integer(exponent);
    }                    
             
    public Iso4217CurrencyCode getCurrency()
    {
        return currency;
    }
        
    public BigInteger getAmount()
    {
        return amount.getValue();
    }
        
    public BigInteger getExponent()
    {
        return exponent.getValue();
    }   
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(currency);
        seq.add(amount);
        seq.add(exponent); 
        
        return new DERSequence(seq);
    }
}
