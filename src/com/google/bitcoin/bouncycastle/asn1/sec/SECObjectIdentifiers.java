package com.google.bitcoin.bouncycastle.asn1.sec;

import com.google.bitcoin.bouncycastle.asn1.DERObjectIdentifier;
import com.google.bitcoin.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public interface SECObjectIdentifiers
{
    /**
     *  ellipticCurve OBJECT IDENTIFIER ::= {
     *        iso(1) identified-organization(3) certicom(132) curve(0)
     *  }
     */
    static final DERObjectIdentifier ellipticCurve = new DERObjectIdentifier("1.3.132.0");

    static final DERObjectIdentifier sect163k1 = new DERObjectIdentifier(ellipticCurve + ".1");
    static final DERObjectIdentifier sect163r1 = new DERObjectIdentifier(ellipticCurve + ".2");
    static final DERObjectIdentifier sect239k1 = new DERObjectIdentifier(ellipticCurve + ".3");
    static final DERObjectIdentifier sect113r1 = new DERObjectIdentifier(ellipticCurve + ".4");
    static final DERObjectIdentifier sect113r2 = new DERObjectIdentifier(ellipticCurve + ".5");
    static final DERObjectIdentifier secp112r1 = new DERObjectIdentifier(ellipticCurve + ".6");
    static final DERObjectIdentifier secp112r2 = new DERObjectIdentifier(ellipticCurve + ".7");
    static final DERObjectIdentifier secp160r1 = new DERObjectIdentifier(ellipticCurve + ".8");
    static final DERObjectIdentifier secp160k1 = new DERObjectIdentifier(ellipticCurve + ".9");
    static final DERObjectIdentifier secp256k1 = new DERObjectIdentifier(ellipticCurve + ".10");
    static final DERObjectIdentifier sect163r2 = new DERObjectIdentifier(ellipticCurve + ".15");
    static final DERObjectIdentifier sect283k1 = new DERObjectIdentifier(ellipticCurve + ".16");
    static final DERObjectIdentifier sect283r1 = new DERObjectIdentifier(ellipticCurve + ".17");
    static final DERObjectIdentifier sect131r1 = new DERObjectIdentifier(ellipticCurve + ".22");
    static final DERObjectIdentifier sect131r2 = new DERObjectIdentifier(ellipticCurve + ".23");
    static final DERObjectIdentifier sect193r1 = new DERObjectIdentifier(ellipticCurve + ".24");
    static final DERObjectIdentifier sect193r2 = new DERObjectIdentifier(ellipticCurve + ".25");
    static final DERObjectIdentifier sect233k1 = new DERObjectIdentifier(ellipticCurve + ".26");
    static final DERObjectIdentifier sect233r1 = new DERObjectIdentifier(ellipticCurve + ".27");
    static final DERObjectIdentifier secp128r1 = new DERObjectIdentifier(ellipticCurve + ".28");
    static final DERObjectIdentifier secp128r2 = new DERObjectIdentifier(ellipticCurve + ".29");
    static final DERObjectIdentifier secp160r2 = new DERObjectIdentifier(ellipticCurve + ".30");
    static final DERObjectIdentifier secp192k1 = new DERObjectIdentifier(ellipticCurve + ".31");
    static final DERObjectIdentifier secp224k1 = new DERObjectIdentifier(ellipticCurve + ".32");
    static final DERObjectIdentifier secp224r1 = new DERObjectIdentifier(ellipticCurve + ".33");
    static final DERObjectIdentifier secp384r1 = new DERObjectIdentifier(ellipticCurve + ".34");
    static final DERObjectIdentifier secp521r1 = new DERObjectIdentifier(ellipticCurve + ".35");
    static final DERObjectIdentifier sect409k1 = new DERObjectIdentifier(ellipticCurve + ".36");
    static final DERObjectIdentifier sect409r1 = new DERObjectIdentifier(ellipticCurve + ".37");
    static final DERObjectIdentifier sect571k1 = new DERObjectIdentifier(ellipticCurve + ".38");
    static final DERObjectIdentifier sect571r1 = new DERObjectIdentifier(ellipticCurve + ".39");

    static final DERObjectIdentifier secp192r1 = X9ObjectIdentifiers.prime192v1;
    static final DERObjectIdentifier secp256r1 = X9ObjectIdentifiers.prime256v1;

}
