package com.google.bitcoin.bouncycastle.asn1.teletrust;

import com.google.bitcoin.bouncycastle.asn1.DERObjectIdentifier;

public interface TeleTrusTObjectIdentifiers
{
    static final String teleTrusTAlgorithm = "1.3.36.3";

    static final DERObjectIdentifier    ripemd160           = new DERObjectIdentifier(teleTrusTAlgorithm + ".2.1");
    static final DERObjectIdentifier    ripemd128           = new DERObjectIdentifier(teleTrusTAlgorithm + ".2.2");
    static final DERObjectIdentifier    ripemd256           = new DERObjectIdentifier(teleTrusTAlgorithm + ".2.3");

    static final String teleTrusTRSAsignatureAlgorithm = teleTrusTAlgorithm + ".3.1";

    static final DERObjectIdentifier    rsaSignatureWithripemd160           = new DERObjectIdentifier(teleTrusTRSAsignatureAlgorithm + ".2");
    static final DERObjectIdentifier    rsaSignatureWithripemd128           = new DERObjectIdentifier(teleTrusTRSAsignatureAlgorithm + ".3");
    static final DERObjectIdentifier    rsaSignatureWithripemd256           = new DERObjectIdentifier(teleTrusTRSAsignatureAlgorithm + ".4");

    static final DERObjectIdentifier    ecSign = new DERObjectIdentifier(teleTrusTAlgorithm + ".3.2");

    static final DERObjectIdentifier    ecSignWithSha1  = new DERObjectIdentifier(ecSign + ".1");
    static final DERObjectIdentifier    ecSignWithRipemd160  = new DERObjectIdentifier(ecSign + ".2");

    static final DERObjectIdentifier ecc_brainpool = new DERObjectIdentifier(teleTrusTAlgorithm + ".3.2.8");
    static final DERObjectIdentifier ellipticCurve = new DERObjectIdentifier(ecc_brainpool + ".1");
    static final DERObjectIdentifier versionOne = new DERObjectIdentifier(ellipticCurve + ".1");    

    static final DERObjectIdentifier brainpoolP160r1 = new DERObjectIdentifier(versionOne + ".1");
    static final DERObjectIdentifier brainpoolP160t1 = new DERObjectIdentifier(versionOne + ".2");
    static final DERObjectIdentifier brainpoolP192r1 = new DERObjectIdentifier(versionOne + ".3");
    static final DERObjectIdentifier brainpoolP192t1 = new DERObjectIdentifier(versionOne + ".4");
    static final DERObjectIdentifier brainpoolP224r1 = new DERObjectIdentifier(versionOne + ".5");
    static final DERObjectIdentifier brainpoolP224t1 = new DERObjectIdentifier(versionOne + ".6");
    static final DERObjectIdentifier brainpoolP256r1 = new DERObjectIdentifier(versionOne + ".7");
    static final DERObjectIdentifier brainpoolP256t1 = new DERObjectIdentifier(versionOne + ".8");
    static final DERObjectIdentifier brainpoolP320r1 = new DERObjectIdentifier(versionOne + ".9");
    static final DERObjectIdentifier brainpoolP320t1 = new DERObjectIdentifier(versionOne+".10");
    static final DERObjectIdentifier brainpoolP384r1 = new DERObjectIdentifier(versionOne+".11");
    static final DERObjectIdentifier brainpoolP384t1 = new DERObjectIdentifier(versionOne+".12");
    static final DERObjectIdentifier brainpoolP512r1 = new DERObjectIdentifier(versionOne+".13");
    static final DERObjectIdentifier brainpoolP512t1 = new DERObjectIdentifier(versionOne+".14");
}
