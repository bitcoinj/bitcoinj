package com.google.bitcoin.bouncycastle.crypto.util;

import com.google.bitcoin.bouncycastle.asn1.ASN1InputStream;
import com.google.bitcoin.bouncycastle.asn1.ASN1Object;
import com.google.bitcoin.bouncycastle.asn1.ASN1Sequence;
import com.google.bitcoin.bouncycastle.asn1.DEREncodable;
import com.google.bitcoin.bouncycastle.asn1.DERInteger;
import com.google.bitcoin.bouncycastle.asn1.DERObject;
import com.google.bitcoin.bouncycastle.asn1.DERObjectIdentifier;
import com.google.bitcoin.bouncycastle.asn1.nist.NISTNamedCurves;
import com.google.bitcoin.bouncycastle.asn1.oiw.ElGamalParameter;
import com.google.bitcoin.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import com.google.bitcoin.bouncycastle.asn1.pkcs.DHParameter;
import com.google.bitcoin.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.google.bitcoin.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.google.bitcoin.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import com.google.bitcoin.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import com.google.bitcoin.bouncycastle.asn1.sec.SECNamedCurves;
import com.google.bitcoin.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import com.google.bitcoin.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.google.bitcoin.bouncycastle.asn1.x509.DSAParameter;
import com.google.bitcoin.bouncycastle.asn1.x9.X962NamedCurves;
import com.google.bitcoin.bouncycastle.asn1.x9.X962Parameters;
import com.google.bitcoin.bouncycastle.asn1.x9.X9ECParameters;
import com.google.bitcoin.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import com.google.bitcoin.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.google.bitcoin.bouncycastle.crypto.params.DHParameters;
import com.google.bitcoin.bouncycastle.crypto.params.DHPrivateKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.DSAParameters;
import com.google.bitcoin.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ECDomainParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ElGamalParameters;
import com.google.bitcoin.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import com.google.bitcoin.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

/**
 * Factory for creating private key objects from PKCS8 PrivateKeyInfo objects.
 */
public class PrivateKeyFactory
{
    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.
     * 
     * @param privateKeyInfoData the PrivateKeyInfo encoding
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(
        byte[] privateKeyInfoData)
        throws IOException
    {
        return createKey(
            PrivateKeyInfo.getInstance(
                ASN1Object.fromByteArray(privateKeyInfoData)));
    }

    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a stream.
     * 
     * @param inStr the stream to read the PrivateKeyInfo encoding from
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(
        InputStream inStr)
        throws IOException
    {
        return createKey(
            PrivateKeyInfo.getInstance(
                new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.
     * 
     * @param keyInfo the PrivateKeyInfo object containing the key material
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(
        PrivateKeyInfo    keyInfo)
        throws IOException
    {
        AlgorithmIdentifier     algId = keyInfo.getAlgorithmId();
        
        if (algId.getObjectId().equals(PKCSObjectIdentifiers.rsaEncryption))
        {
            RSAPrivateKeyStructure  keyStructure = new RSAPrivateKeyStructure((ASN1Sequence)keyInfo.getPrivateKey());

            return new RSAPrivateCrtKeyParameters(
                                        keyStructure.getModulus(),
                                        keyStructure.getPublicExponent(),
                                        keyStructure.getPrivateExponent(),
                                        keyStructure.getPrime1(),
                                        keyStructure.getPrime2(),
                                        keyStructure.getExponent1(),
                                        keyStructure.getExponent2(),
                                        keyStructure.getCoefficient());
        }
        else if (algId.getObjectId().equals(PKCSObjectIdentifiers.dhKeyAgreement))
        {
            DHParameter     params = new DHParameter((ASN1Sequence)keyInfo.getAlgorithmId().getParameters());
            DERInteger      derX = (DERInteger)keyInfo.getPrivateKey();

            BigInteger lVal = params.getL();
            int l = lVal == null ? 0 : lVal.intValue();
            DHParameters dhParams = new DHParameters(params.getP(), params.getG(), null, l);

            return new DHPrivateKeyParameters(derX.getValue(), dhParams);
        }
        else if (algId.getObjectId().equals(OIWObjectIdentifiers.elGamalAlgorithm))
        {
            ElGamalParameter    params = new ElGamalParameter((ASN1Sequence)keyInfo.getAlgorithmId().getParameters());
            DERInteger          derX = (DERInteger)keyInfo.getPrivateKey();

            return new ElGamalPrivateKeyParameters(derX.getValue(), new ElGamalParameters(params.getP(), params.getG()));
        }
        else if (algId.getObjectId().equals(X9ObjectIdentifiers.id_dsa))
        {
            DERInteger derX = (DERInteger)keyInfo.getPrivateKey();
            DEREncodable de = keyInfo.getAlgorithmId().getParameters();

            DSAParameters parameters = null;
            if (de != null)
            {
                DSAParameter params = DSAParameter.getInstance(de.getDERObject());
                parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
            }

            return new DSAPrivateKeyParameters(derX.getValue(), parameters);
        }
        else if (algId.getObjectId().equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            X962Parameters      params = new X962Parameters((DERObject)keyInfo.getAlgorithmId().getParameters());
            ECDomainParameters  dParams = null;
            
            if (params.isNamedCurve())
            {
                DERObjectIdentifier oid = (DERObjectIdentifier)params.getParameters();
                X9ECParameters      ecP = X962NamedCurves.getByOID(oid);

                if (ecP == null)
                {
                    ecP = SECNamedCurves.getByOID(oid);

                    if (ecP == null)
                    {
                        ecP = NISTNamedCurves.getByOID(oid);

                        if (ecP == null)
                        {
                            ecP = TeleTrusTNamedCurves.getByOID(oid);
                        }
                    }
                }

                dParams = new ECDomainParameters(
                                            ecP.getCurve(),
                                            ecP.getG(),
                                            ecP.getN(),
                                            ecP.getH(),
                                            ecP.getSeed());
            }
            else
            {
                X9ECParameters ecP = new X9ECParameters(
                            (ASN1Sequence)params.getParameters());
                dParams = new ECDomainParameters(
                                            ecP.getCurve(),
                                            ecP.getG(),
                                            ecP.getN(),
                                            ecP.getH(),
                                            ecP.getSeed());
            }

            ECPrivateKeyStructure   ec = new ECPrivateKeyStructure((ASN1Sequence)keyInfo.getPrivateKey());

            return new ECPrivateKeyParameters(ec.getKey(), dParams);
        }
        else
        {
            throw new RuntimeException("algorithm identifier in key not recognised");
        }
    }
}
