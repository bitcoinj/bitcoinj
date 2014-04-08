package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.DHDomainParameters;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.asn1.x9.DHValidationParms;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * Factory to create asymmetric public key parameters for asymmetric ciphers from range of
 * ASN.1 encoded SubjectPublicKeyInfo objects.
 */
public class PublicKeyFactory
{
    /**
     * Create a public key from a SubjectPublicKeyInfo encoding
     * 
     * @param keyInfoData the SubjectPublicKeyInfo encoding
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] keyInfoData) throws IOException
    {
        return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(keyInfoData)));
    }

    /**
     * Create a public key from a SubjectPublicKeyInfo encoding read from a stream
     * 
     * @param inStr the stream to read the SubjectPublicKeyInfo encoding from
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr) throws IOException
    {
        return createKey(SubjectPublicKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a public key from the passed in SubjectPublicKeyInfo
     * 
     * @param keyInfo the SubjectPublicKeyInfo containing the key data
     * @return the appropriate key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo) throws IOException
    {
        AlgorithmIdentifier algId = keyInfo.getAlgorithm();

        if (algId.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption)
            || algId.getAlgorithm().equals(X509ObjectIdentifiers.id_ea_rsa))
        {
            RSAPublicKey pubKey = RSAPublicKey.getInstance(keyInfo.parsePublicKey());

            return new RSAKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent());
        }
        else if (algId.getAlgorithm().equals(X9ObjectIdentifiers.dhpublicnumber))
        {
            DHPublicKey dhPublicKey = DHPublicKey.getInstance(keyInfo.parsePublicKey());

            BigInteger y = dhPublicKey.getY().getValue();

            DHDomainParameters dhParams = DHDomainParameters.getInstance(algId.getParameters());

            BigInteger p = dhParams.getP().getValue();
            BigInteger g = dhParams.getG().getValue();
            BigInteger q = dhParams.getQ().getValue();

            BigInteger j = null;
            if (dhParams.getJ() != null)
            {
                j = dhParams.getJ().getValue();
            }

            DHValidationParameters validation = null;
            DHValidationParms dhValidationParms = dhParams.getValidationParms();
            if (dhValidationParms != null)
            {
                byte[] seed = dhValidationParms.getSeed().getBytes();
                BigInteger pgenCounter = dhValidationParms.getPgenCounter().getValue();

                // TODO Check pgenCounter size?

                validation = new DHValidationParameters(seed, pgenCounter.intValue());
            }

            return new DHPublicKeyParameters(y, new DHParameters(p, g, q, j, validation));
        }
        else if (algId.getAlgorithm().equals(PKCSObjectIdentifiers.dhKeyAgreement))
        {
            DHParameter params = DHParameter.getInstance(algId.getParameters());
            ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();

            BigInteger lVal = params.getL();
            int l = lVal == null ? 0 : lVal.intValue();
            DHParameters dhParams = new DHParameters(params.getP(), params.getG(), null, l);

            return new DHPublicKeyParameters(derY.getValue(), dhParams);
        }
        else if (algId.getAlgorithm().equals(OIWObjectIdentifiers.elGamalAlgorithm))
        {
            ElGamalParameter params = ElGamalParameter.getInstance(algId.getParameters());
            ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();

            return new ElGamalPublicKeyParameters(derY.getValue(), new ElGamalParameters(
                params.getP(), params.getG()));
        }
        else if (algId.getAlgorithm().equals(X9ObjectIdentifiers.id_dsa)
            || algId.getAlgorithm().equals(OIWObjectIdentifiers.dsaWithSHA1))
        {
            ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();
            ASN1Encodable de = algId.getParameters();

            DSAParameters parameters = null;
            if (de != null)
            {
                DSAParameter params = DSAParameter.getInstance(de.toASN1Primitive());
                parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
            }

            return new DSAPublicKeyParameters(derY.getValue(), parameters);
        }
        else if (algId.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            X962Parameters params = X962Parameters.getInstance(algId.getParameters());

            X9ECParameters x9;
            ECDomainParameters dParams;

            if (params.isNamedCurve())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();

                x9 = CustomNamedCurves.getByOID(oid);
                if (x9 == null)
                {
                    x9 = ECNamedCurveTable.getByOID(oid);
                }
                dParams = new ECNamedDomainParameters(
                         oid, x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
            }
            else
            {
                x9 = X9ECParameters.getInstance(params.getParameters());
                dParams = new ECDomainParameters(
                         x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
            }

            ASN1OctetString key = new DEROctetString(keyInfo.getPublicKeyData().getBytes());
            X9ECPoint derQ = new X9ECPoint(x9.getCurve(), key);

            return new ECPublicKeyParameters(derQ.getPoint(), dParams);
        }
        else
        {
            throw new RuntimeException("algorithm identifier in key not recognised");
        }
    }
}
