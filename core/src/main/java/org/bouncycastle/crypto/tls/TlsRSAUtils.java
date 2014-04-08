package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class TlsRSAUtils
{
    public static byte[] generateEncryptedPreMasterSecret(TlsContext context, RSAKeyParameters rsaServerPublicKey,
        OutputStream output) throws IOException
    {
        /*
         * Choose a PremasterSecret and send it encrypted to the server
         */
        byte[] premasterSecret = new byte[48];
        context.getSecureRandom().nextBytes(premasterSecret);
        TlsUtils.writeVersion(context.getClientVersion(), premasterSecret, 0);

        PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
        encoding.init(true, new ParametersWithRandom(rsaServerPublicKey, context.getSecureRandom()));

        try
        {
            byte[] encryptedPreMasterSecret = encoding.processBlock(premasterSecret, 0, premasterSecret.length);

            if (TlsUtils.isSSL(context))
            {
                // TODO Do any SSLv3 servers actually expect the length?
                output.write(encryptedPreMasterSecret);
            }
            else
            {
                TlsUtils.writeOpaque16(encryptedPreMasterSecret, output);
            }
        }
        catch (InvalidCipherTextException e)
        {
            /*
             * This should never happen, only during decryption.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return premasterSecret;
    }

    public static byte[] safeDecryptPreMasterSecret(TlsContext context, TlsEncryptionCredentials encryptionCredentials,
        byte[] encryptedPreMasterSecret)
    {
        /*
         * RFC 5246 7.4.7.1.
         */

        ProtocolVersion clientVersion = context.getClientVersion();

        // TODO Provide as configuration option?
        boolean versionNumberCheckDisabled = false;

        /*
         * See notes regarding Bleichenbacher/Klima attack. The code here implements the first
         * construction proposed there, which is RECOMMENDED.
         */
        byte[] R = new byte[48];
        context.getSecureRandom().nextBytes(R);

        byte[] M = TlsUtils.EMPTY_BYTES;
        try
        {
            M = encryptionCredentials.decryptPreMasterSecret(encryptedPreMasterSecret);
        }
        catch (Exception e)
        {
            /*
             * In any case, a TLS server MUST NOT generate an alert if processing an
             * RSA-encrypted premaster secret message fails, or the version number is not as
             * expected. Instead, it MUST continue the handshake with a randomly generated
             * premaster secret.
             */
        }

        if (M.length != 48)
        {
            TlsUtils.writeVersion(clientVersion, R, 0);
            return R;
        }

        /*
         * If ClientHello.client_version is TLS 1.1 or higher, server implementations MUST
         * check the version number [..].
         */
        if (versionNumberCheckDisabled && clientVersion.isEqualOrEarlierVersionOf(ProtocolVersion.TLSv10))
        {
            /*
             * If the version number is TLS 1.0 or earlier, server implementations SHOULD
             * check the version number, but MAY have a configuration option to disable the
             * check.
             */
        }
        else
        {
            /*
             * Note that explicitly constructing the pre_master_secret with the
             * ClientHello.client_version produces an invalid master_secret if the client
             * has sent the wrong version in the original pre_master_secret.
             */
            TlsUtils.writeVersion(clientVersion, M, 0);
        }

        return M;
    }
}
