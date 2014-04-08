package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

public class ServerDHParams
{
    protected DHPublicKeyParameters publicKey;

    public ServerDHParams(DHPublicKeyParameters publicKey)
    {
        if (publicKey == null)
        {
            throw new IllegalArgumentException("'publicKey' cannot be null");
        }

        this.publicKey = publicKey;
    }

    public DHPublicKeyParameters getPublicKey()
    {
        return publicKey;
    }

    /**
     * Encode this {@link ServerDHParams} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        DHParameters dhParameters = publicKey.getParameters();
        BigInteger Ys = publicKey.getY();

        TlsDHUtils.writeDHParameter(dhParameters.getP(), output);
        TlsDHUtils.writeDHParameter(dhParameters.getG(), output);
        TlsDHUtils.writeDHParameter(Ys, output);
    }

    /**
     * Parse a {@link ServerDHParams} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link ServerDHParams} object.
     * @throws IOException
     */
    public static ServerDHParams parse(InputStream input) throws IOException
    {
        BigInteger p = TlsDHUtils.readDHParameter(input);
        BigInteger g = TlsDHUtils.readDHParameter(input);
        BigInteger Ys = TlsDHUtils.readDHParameter(input);

        return new ServerDHParams(new DHPublicKeyParameters(Ys, new DHParameters(p, g)));
    }
}
