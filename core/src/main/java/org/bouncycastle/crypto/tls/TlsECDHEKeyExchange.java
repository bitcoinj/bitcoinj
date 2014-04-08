package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * ECDHE key exchange (see RFC 4492)
 */
public class TlsECDHEKeyExchange
    extends TlsECDHKeyExchange
{
    protected TlsSignerCredentials serverCredentials = null;

    public TlsECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats)
    {
        super(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        if (!(serverCredentials instanceof TlsSignerCredentials))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsSignerCredentials)serverCredentials;
    }

    public byte[] generateServerKeyExchange()
        throws IOException
    {
        /*
         * First we try to find a supported named curve from the client's list.
         */
        int namedCurve = -1;
        if (namedCurves == null)
        {
            // TODO Let the peer choose the default named curve
            namedCurve = NamedCurve.secp256r1;
        }
        else
        {
            for (int i = 0; i < namedCurves.length; ++i)
            {
                int entry = namedCurves[i];
                if (NamedCurve.isValid(entry) && TlsECCUtils.isSupportedNamedCurve(entry))
                {
                    namedCurve = entry;
                    break;
                }
            }
        }

        ECDomainParameters curve_params = null;
        if (namedCurve >= 0)
        {
            curve_params = TlsECCUtils.getParametersForNamedCurve(namedCurve);
        }
        else
        {
            /*
             * If no named curves are suitable, check if the client supports explicit curves.
             */
            if (Arrays.contains(namedCurves, NamedCurve.arbitrary_explicit_prime_curves))
            {
                curve_params = TlsECCUtils.getParametersForNamedCurve(NamedCurve.secp256r1);
            }
            else if (Arrays.contains(namedCurves, NamedCurve.arbitrary_explicit_char2_curves))
            {
                curve_params = TlsECCUtils.getParametersForNamedCurve(NamedCurve.sect283r1);
            }
        }

        if (curve_params == null)
        {
            /*
             * NOTE: We shouldn't have negotiated ECDHE key exchange since we apparently can't find
             * a suitable curve.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        AsymmetricCipherKeyPair kp = TlsECCUtils.generateECKeyPair(context.getSecureRandom(), curve_params);
        this.ecAgreePrivateKey = (ECPrivateKeyParameters)kp.getPrivate();

        DigestInputBuffer buf = new DigestInputBuffer();

        if (namedCurve < 0)
        {
            TlsECCUtils.writeExplicitECParameters(clientECPointFormats, curve_params, buf);
        }
        else
        {
            TlsECCUtils.writeNamedECParameters(namedCurve, buf);
        }

        ECPublicKeyParameters ecPublicKey = (ECPublicKeyParameters) kp.getPublic();
        TlsECCUtils.writeECPoint(clientECPointFormats, ecPublicKey.getQ(), buf);

        /*
         * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
         */
        SignatureAndHashAlgorithm signatureAndHashAlgorithm;
        Digest d;

        if (TlsUtils.isTLSv12(context))
        {
            signatureAndHashAlgorithm = serverCredentials.getSignatureAndHashAlgorithm();
            if (signatureAndHashAlgorithm == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            d = TlsUtils.createHash(signatureAndHashAlgorithm.getHash());
        }
        else
        {
            signatureAndHashAlgorithm = null;
            d = new CombinedHash();
        }

        SecurityParameters securityParameters = context.getSecurityParameters();
        d.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        d.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        buf.updateDigest(d);

        byte[] hash = new byte[d.getDigestSize()];
        d.doFinal(hash, 0);

        byte[] signature = serverCredentials.generateCertificateSignature(hash);

        DigitallySigned signed_params = new DigitallySigned(signatureAndHashAlgorithm, signature);
        signed_params.encode(buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input)
        throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParameters();

        SignerInputBuffer buf = new SignerInputBuffer();
        InputStream teeIn = new TeeInputStream(input, buf);

        ECDomainParameters curve_params = TlsECCUtils.readECParameters(namedCurves, clientECPointFormats, teeIn);

        byte[] point = TlsUtils.readOpaque8(teeIn);

        DigitallySigned signed_params = DigitallySigned.parse(context, input);

        Signer signer = initVerifyer(tlsSigner, signed_params.getAlgorithm(), securityParameters);
        buf.updateSigner(signer);
        if (!signer.verifySignature(signed_params.getSignature()))
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }

        this.ecAgreePublicKey = TlsECCUtils.validateECPublicKey(TlsECCUtils.deserializeECPublicKey(
            clientECPointFormats, curve_params, point));
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException
    {
        /*
         * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
         * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
         * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
         * these algorithms.
         */
        short[] types = certificateRequest.getCertificateTypes();
        for (int i = 0; i < types.length; ++i)
        {
            switch (types[i])
            {
            case ClientCertificateType.rsa_sign:
            case ClientCertificateType.dss_sign:
            case ClientCertificateType.ecdsa_sign:
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
        if (clientCredentials instanceof TlsSignerCredentials)
        {
            // OK
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected Signer initVerifyer(TlsSigner tlsSigner, SignatureAndHashAlgorithm algorithm, SecurityParameters securityParameters)
    {
        Signer signer = tlsSigner.createVerifyer(algorithm, this.serverPublicKey);
        signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return signer;
    }
}
