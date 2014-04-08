package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.util.io.TeeInputStream;

public class TlsDHEKeyExchange
    extends TlsDHKeyExchange
{
    protected TlsSignerCredentials serverCredentials = null;

    public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, DHParameters dhParameters)
    {
        super(keyExchange, supportedSignatureAlgorithms, dhParameters);
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
        if (this.dhParameters == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        DigestInputBuffer buf = new DigestInputBuffer();

        this.dhAgreeServerPrivateKey = TlsDHUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(),
            this.dhParameters, buf);

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

        ServerDHParams params = ServerDHParams.parse(teeIn);

        DigitallySigned signed_params = DigitallySigned.parse(context, input);

        Signer signer = initVerifyer(tlsSigner, signed_params.getAlgorithm(), securityParameters);
        buf.updateSigner(signer);
        if (!signer.verifySignature(signed_params.getSignature()))
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }

        this.dhAgreeServerPublicKey = TlsDHUtils.validateDHPublicKey(params.getPublicKey());
    }

    protected Signer initVerifyer(TlsSigner tlsSigner, SignatureAndHashAlgorithm algorithm, SecurityParameters securityParameters)
    {
        Signer signer = tlsSigner.createVerifyer(algorithm, this.serverPublicKey);
        signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return signer;
    }
}
