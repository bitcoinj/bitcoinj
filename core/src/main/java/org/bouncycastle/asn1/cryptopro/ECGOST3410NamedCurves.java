package org.bouncycastle.asn1.cryptopro;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;

/**
 * table of the available named parameters for GOST 3410-2001.
 */
public class ECGOST3410NamedCurves
{
    static final Hashtable objIds = new Hashtable();
    static final Hashtable params = new Hashtable();
    static final Hashtable names = new Hashtable();

    static
    {
        BigInteger mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319");
        BigInteger mod_q = new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");

        ECCurve.Fp curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"), // a
            new BigInteger("166"), // b
            mod_q,
            ECConstants.ONE);

        ECDomainParameters ecParams = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("1"), // x
                new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612")), // y
            mod_q);

        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A, ecParams);  

        mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319");
        mod_q = new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");

        curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"),
            new BigInteger("166"),
            mod_q,
            ECConstants.ONE);

        ecParams = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("1"), // x
                new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612")), // y
            mod_q);

        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA, ecParams); 

        mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823193"); //p
        mod_q = new BigInteger("57896044618658097711785492504343953927102133160255826820068844496087732066703"); //q

        curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823190"), // a
            new BigInteger("28091019353058090096996979000309560759124368558014865957655842872397301267595"), // b
            mod_q,
            ECConstants.ONE);

        ecParams = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("1"), // x
                new BigInteger("28792665814854611296992347458380284135028636778229113005756334730996303888124")), // y
            mod_q); // q

        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B, ecParams);  

        mod_p = new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502619");
        mod_q = new BigInteger("70390085352083305199547718019018437840920882647164081035322601458352298396601");

        curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502616"),
            new BigInteger("32858"),
            mod_q,
            ECConstants.ONE);

        ecParams = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("0"),
                new BigInteger("29818893917731240733471273240314769927240550812383695689146495261604565990247")),
            mod_q);

        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB, ecParams);  

        mod_p = new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502619"); //p
        mod_q = new BigInteger("70390085352083305199547718019018437840920882647164081035322601458352298396601"); //q
        curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502616"), // a
            new BigInteger("32858"), // b
            mod_q,
            ECConstants.ONE);

        ecParams = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("0"), // x
                new BigInteger("29818893917731240733471273240314769927240550812383695689146495261604565990247")), // y
            mod_q); // q

        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C, ecParams); 

        objIds.put("GostR3410-2001-CryptoPro-A", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A);
        objIds.put("GostR3410-2001-CryptoPro-B", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B);
        objIds.put("GostR3410-2001-CryptoPro-C", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C);
        objIds.put("GostR3410-2001-CryptoPro-XchA", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA);
        objIds.put("GostR3410-2001-CryptoPro-XchB", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB);

        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A, "GostR3410-2001-CryptoPro-A");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B, "GostR3410-2001-CryptoPro-B");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C, "GostR3410-2001-CryptoPro-C");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA, "GostR3410-2001-CryptoPro-XchA");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB, "GostR3410-2001-CryptoPro-XchB");
    }

    /**
     * return the ECDomainParameters object for the given OID, null if it 
     * isn't present.
     *
     * @param oid an object identifier representing a named parameters, if present.
     */
    public static ECDomainParameters getByOID(
        ASN1ObjectIdentifier  oid)
    {
        return (ECDomainParameters)params.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for parameters
     * contained in this structure.
     */
    public static Enumeration getNames()
    {
        return objIds.keys();
    }

    public static ECDomainParameters getByName(
        String  name)
    {
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)objIds.get(name);

        if (oid != null)
        {
            return (ECDomainParameters)params.get(oid);
        }

        return null;
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(
        ASN1ObjectIdentifier  oid)
    {
        return (String)names.get(oid);
    }
    
    public static ASN1ObjectIdentifier getOID(String name)
    {
        return (ASN1ObjectIdentifier)objIds.get(name);
    }
}
