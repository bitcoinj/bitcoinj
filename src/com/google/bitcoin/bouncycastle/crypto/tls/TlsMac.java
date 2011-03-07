package com.google.bitcoin.bouncycastle.crypto.tls;

import com.google.bitcoin.bouncycastle.crypto.Digest;
import com.google.bitcoin.bouncycastle.crypto.macs.HMac;
import com.google.bitcoin.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A generic TLS MAC implementation, which can be used with any kind of
 * Digest to act as an HMAC.
 */
public class TlsMac
{
    private long seqNo;
    private HMac mac;

    /**
     * Generate a new instance of an TlsMac.
     *
     * @param digest    The digest to use.
     * @param key_block A byte-array where the key for this mac is located.
     * @param offset    The number of bytes to skip, before the key starts in the buffer.
     * @param len       The length of the key.
     */
    protected TlsMac(Digest digest, byte[] key_block, int offset, int len)
    {
        this.mac = new HMac(digest);
        KeyParameter param = new KeyParameter(key_block, offset, len);
        this.mac.init(param);
        this.seqNo = 0;
    }

    /**
     * @return The Keysize of the mac.
     */
    protected int getSize()
    {
        return mac.getMacSize();
    }

    /**
     * Calculate the mac for some given data.
     * <p/>
     * TlsMac will keep track of the sequence number internally.
     *
     * @param type    The message type of the message.
     * @param message A byte-buffer containing the message.
     * @param offset  The number of bytes to skip, before the message starts.
     * @param len     The length of the message.
     * @return A new byte-buffer containing the mac value.
     */
    protected byte[] calculateMac(short type, byte[] message, int offset, int len)
    {
        try
        {
            ByteArrayOutputStream bosMac = new ByteArrayOutputStream();
            TlsUtils.writeUint64(seqNo++, bosMac);
            TlsUtils.writeUint8(type, bosMac);
            TlsUtils.writeVersion(bosMac);
            TlsUtils.writeUint16(len, bosMac);
            bosMac.write(message, offset, len);
            byte[] macData = bosMac.toByteArray();
            mac.update(macData, 0, macData.length);
            byte[] result = new byte[mac.getMacSize()];
            mac.doFinal(result, 0);
            mac.reset();
            return result;
        }
        catch (IOException e)
        {
            // This should never happen
            throw new IllegalStateException("Internal error during mac calculation");
        }
    }

}
