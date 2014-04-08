package org.bouncycastle.crypto.ec;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.djb.Curve25519;
import org.bouncycastle.math.ec.custom.sec.SecP192K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP224K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP224R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;
import org.bouncycastle.math.ec.endo.GLVTypeBEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBParameters;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class CustomNamedCurves
{
    private static ECCurve configureCurve(ECCurve curve)
    {
        return curve;
    }

    private static ECCurve configureCurveGLV(ECCurve c, GLVTypeBParameters p)
    {
        return c.configure().setEndomorphism(new GLVTypeBEndomorphism(c, p)).create();
    }

    /*
     * curve25519
     */
    static X9ECParametersHolder curve25519 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new Curve25519());

            /*
             * NOTE: Curve25519 was specified in Montgomery form. Rewriting in Weierstrass form
             * involves substitution of variables, so the base-point x coordinate is 9 + (486662 / 3).
             * 
             * The Curve25519 paper doesn't say which of the two possible y values the base
             * point has. The choice here is guided by language in the Ed25519 paper.
             * 
             * (The other possible y value is 5F51E65E475F794B1FE122D388B72EB36DC2B28192839E4DD6163A5D81312C14) 
             */
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A"
                + "20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp192k1
     */
    static X9ECParametersHolder secp192k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            GLVTypeBParameters glv = new GLVTypeBParameters(
                new BigInteger("bb85691939b869c1d087f601554b96b80cb4f55b35f433c2", 16),
                new BigInteger("3d84f26c12238d7b4f3d516613c1759033b1a5800175d0b1", 16),
                new BigInteger[]{
                    new BigInteger("71169be7330b3038edb025f1", 16),
                    new BigInteger("-b3fb3400dec5c4adceb8655c", 16) },
                new BigInteger[]{
                    new BigInteger("12511cfe811d0f4e6bc688b4d", 16),
                    new BigInteger("71169be7330b3038edb025f1", 16) },
                new BigInteger("1c45a6f9ccc2cc0e3b6c097c7", 16),
                new BigInteger("2cfecd0037b1712b73ae19575", 16),
                194);
            ECCurve curve = configureCurveGLV(new SecP192K1Curve(), glv);
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
                + "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp192r1
     */
    static X9ECParametersHolder secp192r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("3045AE6FC8422F64ED579528D38120EAE12196D5");
            ECCurve curve = configureCurve(new SecP192R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
                + "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp224k1
     */
    static X9ECParametersHolder secp224k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            GLVTypeBParameters glv = new GLVTypeBParameters(
                new BigInteger("fe0e87005b4e83761908c5131d552a850b3f58b749c37cf5b84d6768", 16),
                new BigInteger("60dcd2104c4cbc0be6eeefc2bdd610739ec34e317f9b33046c9e4788", 16),
                new BigInteger[]{
                    new BigInteger("6b8cf07d4ca75c88957d9d670591", 16),
                    new BigInteger("-b8adf1378a6eb73409fa6c9c637d", 16) },
                new BigInteger[]{
                    new BigInteger("1243ae1b4d71613bc9f780a03690e", 16),
                    new BigInteger("6b8cf07d4ca75c88957d9d670591", 16) },
                new BigInteger("35c6783ea653ae444abeceb382c82", 16),
                new BigInteger("5c56f89bc5375b9a04fd364e31bdd", 16),
                227);
            ECCurve curve = configureCurveGLV(new SecP224K1Curve(), glv);
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"
                + "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp224r1
     */
    static X9ECParametersHolder secp224r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
            ECCurve curve = configureCurve(new SecP224R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp256k1
     */
    static X9ECParametersHolder secp256k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            GLVTypeBParameters glv = new GLVTypeBParameters(
                new BigInteger("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", 16),
                new BigInteger("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", 16),
                new BigInteger[]{
                    new BigInteger("3086d221a7d46bcde86c90e49284eb15", 16),
                    new BigInteger("-e4437ed6010e88286f547fa90abfe4c3", 16) },
                new BigInteger[]{
                    new BigInteger("114ca50f7a8e2f3f657c1108d9d44cfd8", 16),
                    new BigInteger("3086d221a7d46bcde86c90e49284eb15", 16) },
                new BigInteger("c21b48869f51af37a1b243924a13ac55", 16),
                new BigInteger("3910dfb58043a20a1bd51fea42aff9311", 16),
                258);
            ECCurve curve = configureCurveGLV(new SecP256K1Curve(), glv);
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp256r1
     */
    static X9ECParametersHolder secp256r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("C49D360886E704936A6678E1139D26B7819F7E90");
            ECCurve curve = configureCurve(new SecP256R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp384r1
     */
    static X9ECParametersHolder secp384r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("A335926AA319A27A1D00896A6773A4827ACDAC73");
            ECCurve curve = configureCurve(new SecP384R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
                + "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp521r1
     */
    static X9ECParametersHolder secp521r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("D09E8800291CB85396CC6717393284AAA0DA64BA");
            ECCurve curve = configureCurve(new SecP521R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
                + "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    static final Hashtable nameToCurve = new Hashtable();
    static final Hashtable nameToOID = new Hashtable();
    static final Hashtable oidToCurve = new Hashtable();
    static final Hashtable oidToName = new Hashtable();

    static void defineCurve(String name, X9ECParametersHolder holder)
    {
        nameToCurve.put(name, holder);
    }

    static void defineCurveWithOID(String name, ASN1ObjectIdentifier oid, X9ECParametersHolder holder)
    {
        nameToCurve.put(name, holder);
        nameToOID.put(name, oid);
        oidToName.put(oid, name);
        oidToCurve.put(oid, holder);
    }

    static void defineCurveAlias(String alias, ASN1ObjectIdentifier oid)
    {
        alias = Strings.toLowerCase(alias);
        nameToOID.put(alias, oid);
        nameToCurve.put(alias, oidToCurve.get(oid));
    }

    static
    {
        defineCurve("curve25519", curve25519);

        defineCurveWithOID("secp192k1", SECObjectIdentifiers.secp192k1, secp192k1);
        defineCurveWithOID("secp192r1", SECObjectIdentifiers.secp192r1, secp192r1);
        defineCurveWithOID("secp224k1", SECObjectIdentifiers.secp224k1, secp224k1);
        defineCurveWithOID("secp224r1", SECObjectIdentifiers.secp224r1, secp224r1);
        defineCurveWithOID("secp256k1", SECObjectIdentifiers.secp256k1, secp256k1);
        defineCurveWithOID("secp256r1", SECObjectIdentifiers.secp256r1, secp256r1);
        defineCurveWithOID("secp384r1", SECObjectIdentifiers.secp384r1, secp384r1);
        defineCurveWithOID("secp521r1", SECObjectIdentifiers.secp521r1, secp521r1);

        defineCurveAlias("P-192", SECObjectIdentifiers.secp192r1);
        defineCurveAlias("P-224", SECObjectIdentifiers.secp224r1);
        defineCurveAlias("P-256", SECObjectIdentifiers.secp256r1);
        defineCurveAlias("P-384", SECObjectIdentifiers.secp384r1);
        defineCurveAlias("P-521", SECObjectIdentifiers.secp521r1);
    }

    public static X9ECParameters getByName(String name)
    {
        X9ECParametersHolder holder = (X9ECParametersHolder)nameToCurve.get(Strings.toLowerCase(name));
        return holder == null ? null : holder.getParameters();
    }

    /**
     * return the X9ECParameters object for the named curve represented by the passed in object
     * identifier. Null if the curve isn't present.
     * 
     * @param oid
     *            an object identifier representing a named curve, if present.
     */
    public static X9ECParameters getByOID(ASN1ObjectIdentifier oid)
    {
        X9ECParametersHolder holder = (X9ECParametersHolder)oidToCurve.get(oid);
        return holder == null ? null : holder.getParameters();
    }

    /**
     * return the object identifier signified by the passed in name. Null if there is no object
     * identifier associated with name.
     * 
     * @return the object identifier associated with name, if present.
     */
    public static ASN1ObjectIdentifier getOID(String name)
    {
        return (ASN1ObjectIdentifier)nameToOID.get(Strings.toLowerCase(name));
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(ASN1ObjectIdentifier oid)
    {
        return (String)oidToName.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves contained in this structure.
     */
    public static Enumeration getNames()
    {
        return nameToCurve.keys();
    }
}
