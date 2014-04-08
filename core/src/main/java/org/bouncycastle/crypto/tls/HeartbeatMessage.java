package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class HeartbeatMessage
{
    protected short type;
    protected byte[] payload;
    protected int paddingLength;

    public HeartbeatMessage(short type, byte[] payload, int paddingLength)
    {
        if (!HeartbeatMessageType.isValid(type))
        {
            throw new IllegalArgumentException("'type' is not a valid HeartbeatMessageType value");
        }
        if (payload == null || payload.length >= (1 << 16))
        {
            throw new IllegalArgumentException("'payload' must have length < 2^16");
        }
        if (paddingLength < 16)
        {
            throw new IllegalArgumentException("'paddingLength' must be at least 16");
        }

        this.type = type;
        this.payload = payload;
        this.paddingLength = paddingLength;
    }

    /**
     * Encode this {@link HeartbeatMessage} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(TlsContext context, OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(type, output);

        TlsUtils.checkUint16(payload.length);
        TlsUtils.writeUint16(payload.length, output);
        output.write(payload);

        byte[] padding = new byte[paddingLength];
        context.getSecureRandom().nextBytes(padding);
        output.write(padding);
    }

    /**
     * Parse a {@link HeartbeatMessage} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link HeartbeatMessage} object.
     * @throws IOException
     */
    public static HeartbeatMessage parse(InputStream input) throws IOException
    {
        short type = TlsUtils.readUint8(input);
        if (!HeartbeatMessageType.isValid(type))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        int payload_length = TlsUtils.readUint16(input);

        PayloadBuffer buf = new PayloadBuffer();
        Streams.pipeAll(input, buf);

        byte[] payload = buf.toTruncatedByteArray(payload_length);
        if (payload == null)
        {
            /*
             * RFC 6520 4. If the payload_length of a received HeartbeatMessage is too large, the
             * received HeartbeatMessage MUST be discarded silently.
             */
            return null;
        }

        int padding_length = buf.size() - payload.length;

        return new HeartbeatMessage(type, payload, padding_length);
    }

    static class PayloadBuffer extends ByteArrayOutputStream
    {
        byte[] toTruncatedByteArray(int payloadLength)
        {
            /*
             * RFC 6520 4. The padding_length MUST be at least 16.
             */
            int minimumCount = payloadLength + 16;
            if (count < minimumCount)
            {
                return null;
            }
            return Arrays.copyOf(buf, payloadLength);
        }
    }
}
