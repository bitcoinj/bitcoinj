package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS 1.0-1.2 / SSLv3 block cipher. This can be used for AES or 3DES for example.
 */
public class TlsBlockCipher
    implements TlsCipher
{
    protected TlsContext context;
    protected byte[] randomData;
    protected boolean useExplicitIV;
    private boolean encryptThenMAC;

    protected BlockCipher encryptCipher;
    protected BlockCipher decryptCipher;

    protected TlsMac writeMac;
    protected TlsMac readMac;

    public TlsMac getWriteMac()
    {
        return writeMac;
    }

    public TlsMac getReadMac()
    {
        return readMac;
    }

    public TlsBlockCipher(TlsContext context, BlockCipher clientWriteCipher, BlockCipher serverWriteCipher,
        Digest clientWriteDigest, Digest serverWriteDigest, int cipherKeySize) throws IOException
    {
        this.context = context;

        this.randomData = new byte[256];
        context.getSecureRandom().nextBytes(randomData);

        this.useExplicitIV = TlsUtils.isTLSv11(context);
        this.encryptThenMAC = context.getSecurityParameters().encryptThenMAC;

        int key_block_size = (2 * cipherKeySize) + clientWriteDigest.getDigestSize()
            + serverWriteDigest.getDigestSize();

        // From TLS 1.1 onwards, block ciphers don't need client_write_IV
        if (!useExplicitIV)
        {
            key_block_size += clientWriteCipher.getBlockSize() + serverWriteCipher.getBlockSize();
        }

        byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        TlsMac clientWriteMac = new TlsMac(context, clientWriteDigest, key_block, offset,
            clientWriteDigest.getDigestSize());
        offset += clientWriteDigest.getDigestSize();
        TlsMac serverWriteMac = new TlsMac(context, serverWriteDigest, key_block, offset,
            serverWriteDigest.getDigestSize());
        offset += serverWriteDigest.getDigestSize();

        KeyParameter client_write_key = new KeyParameter(key_block, offset, cipherKeySize);
        offset += cipherKeySize;
        KeyParameter server_write_key = new KeyParameter(key_block, offset, cipherKeySize);
        offset += cipherKeySize;

        byte[] client_write_IV, server_write_IV;
        if (useExplicitIV)
        {
            client_write_IV = new byte[clientWriteCipher.getBlockSize()];
            server_write_IV = new byte[serverWriteCipher.getBlockSize()];
        }
        else
        {
            client_write_IV = Arrays.copyOfRange(key_block, offset, offset + clientWriteCipher.getBlockSize());
            offset += clientWriteCipher.getBlockSize();
            server_write_IV = Arrays.copyOfRange(key_block, offset, offset + serverWriteCipher.getBlockSize());
            offset += serverWriteCipher.getBlockSize();
        }

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        CipherParameters encryptParams, decryptParams;
        if (context.isServer())
        {
            this.writeMac = serverWriteMac;
            this.readMac = clientWriteMac;
            this.encryptCipher = serverWriteCipher;
            this.decryptCipher = clientWriteCipher;
            encryptParams = new ParametersWithIV(server_write_key, server_write_IV);
            decryptParams = new ParametersWithIV(client_write_key, client_write_IV);
        }
        else
        {
            this.writeMac = clientWriteMac;
            this.readMac = serverWriteMac;
            this.encryptCipher = clientWriteCipher;
            this.decryptCipher = serverWriteCipher;
            encryptParams = new ParametersWithIV(client_write_key, client_write_IV);
            decryptParams = new ParametersWithIV(server_write_key, server_write_IV);
        }

        this.encryptCipher.init(true, encryptParams);
        this.decryptCipher.init(false, decryptParams);
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();

        int plaintextLimit = ciphertextLimit;

        // An explicit IV consumes 1 block
        if (useExplicitIV)
        {
            plaintextLimit -= blockSize;
        }

        // Leave room for the MAC, and require block-alignment
        if (encryptThenMAC)
        {
            plaintextLimit -= macSize;
            plaintextLimit -= plaintextLimit % blockSize;
        }
        else
        {
            plaintextLimit -= plaintextLimit % blockSize;
            plaintextLimit -= macSize;
        }

        // Minimum 1 byte of padding
        --plaintextLimit;

        return plaintextLimit;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();

        ProtocolVersion version = context.getServerVersion();

        int enc_input_length = len;
        if (!encryptThenMAC)
        {
            enc_input_length += macSize;
        }

        int padding_length = blockSize - 1 - (enc_input_length % blockSize);

        // TODO[DTLS] Consider supporting in DTLS (without exceeding send limit though)
        if (!version.isDTLS() && !version.isSSL())
        {
            // Add a random number of extra blocks worth of padding
            int maxExtraPadBlocks = (255 - padding_length) / blockSize;
            int actualExtraPadBlocks = chooseExtraPadBlocks(context.getSecureRandom(), maxExtraPadBlocks);
            padding_length += actualExtraPadBlocks * blockSize;
        }

        int totalSize = len + macSize + padding_length + 1;
        if (useExplicitIV)
        {
            totalSize += blockSize;
        }

        byte[] outBuf = new byte[totalSize];
        int outOff = 0;

        if (useExplicitIV)
        {
            byte[] explicitIV = new byte[blockSize];
            context.getSecureRandom().nextBytes(explicitIV);

            encryptCipher.init(true, new ParametersWithIV(null, explicitIV));

            System.arraycopy(explicitIV, 0, outBuf, outOff, blockSize);
            outOff += blockSize;
        }

        int blocks_start = outOff;

        System.arraycopy(plaintext, offset, outBuf, outOff, len);
        outOff += len;

        if (!encryptThenMAC)
        {
            byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);
            System.arraycopy(mac, 0, outBuf, outOff, mac.length);
            outOff += mac.length;
        }

        for (int i = 0; i <= padding_length; i++)
        {
            outBuf[outOff++] = (byte)padding_length;
        }

        for (int i = blocks_start; i < outOff; i += blockSize)
        {
            encryptCipher.processBlock(outBuf, i, outBuf, i);
        }

        if (encryptThenMAC)
        {
            byte[] mac = writeMac.calculateMac(seqNo, type, outBuf, 0, outOff);
            System.arraycopy(mac, 0, outBuf, outOff, mac.length);
            outOff += mac.length;
        }

//        assert outBuf.length == outOff;

        return outBuf;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        int blockSize = decryptCipher.getBlockSize();
        int macSize = readMac.getSize();

        int minLen = blockSize;
        if (encryptThenMAC)
        {
            minLen += macSize;
        }
        else
        {
            minLen = Math.max(minLen, macSize + 1);
        }

        if (useExplicitIV)
        {
            minLen += blockSize;
        }

        if (len < minLen)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int blocks_length = len;
        if (encryptThenMAC)
        {
            blocks_length -= macSize;
        }

        if (blocks_length % blockSize != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decryption_failed);
        }

        if (encryptThenMAC)
        {
            int end = offset + len;
            byte[] receivedMac = Arrays.copyOfRange(ciphertext, end - macSize, end);
            byte[] calculatedMac = readMac.calculateMac(seqNo, type, ciphertext, offset, len - macSize);

            boolean badMac = !Arrays.constantTimeAreEqual(calculatedMac, receivedMac);

            if (badMac)
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            }
        }

        if (useExplicitIV)
        {
            decryptCipher.init(false, new ParametersWithIV(null, ciphertext, offset, blockSize));

            offset += blockSize;
            blocks_length -= blockSize;
        }

        for (int i = 0; i < blocks_length; i += blockSize)
        {
            decryptCipher.processBlock(ciphertext, offset + i, ciphertext, offset + i);
        }

        // If there's anything wrong with the padding, this will return zero
        int totalPad = checkPaddingConstantTime(ciphertext, offset, blocks_length, blockSize, encryptThenMAC ? 0 : macSize);

        int dec_output_length = blocks_length - totalPad;

        if (!encryptThenMAC)
        {
            dec_output_length -= macSize;
            int macInputLen = dec_output_length;
            int macOff = offset + macInputLen;
            byte[] receivedMac = Arrays.copyOfRange(ciphertext, macOff, macOff + macSize);
            byte[] calculatedMac = readMac.calculateMacConstantTime(seqNo, type, ciphertext, offset, macInputLen,
                blocks_length - macSize, randomData);

            boolean badMac = !Arrays.constantTimeAreEqual(calculatedMac, receivedMac);

            if (badMac || totalPad == 0)
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            }
        }

        return Arrays.copyOfRange(ciphertext, offset, offset + dec_output_length);
    }

    protected int checkPaddingConstantTime(byte[] buf, int off, int len, int blockSize, int macSize)
    {
        int end = off + len;
        byte lastByte = buf[end - 1];
        int padlen = lastByte & 0xff;
        int totalPad = padlen + 1;

        int dummyIndex = 0;
        byte padDiff = 0;

        if ((TlsUtils.isSSL(context) && totalPad > blockSize) || (macSize + totalPad > len))
        {
            totalPad = 0;
        }
        else
        {
            int padPos = end - totalPad;
            do
            {
                padDiff |= (buf[padPos++] ^ lastByte);
            }
            while (padPos < end);

            dummyIndex = totalPad;

            if (padDiff != 0)
            {
                totalPad = 0;
            }
        }

        // Run some extra dummy checks so the number of checks is always constant
        {
            byte[] dummyPad = randomData;
            while (dummyIndex < 256)
            {
                padDiff |= (dummyPad[dummyIndex++] ^ lastByte);
            }
            // Ensure the above loop is not eliminated
            dummyPad[0] ^= padDiff;
        }

        return totalPad;
    }

    protected int chooseExtraPadBlocks(SecureRandom r, int max)
    {
        // return r.nextInt(max + 1);

        int x = r.nextInt();
        int n = lowestBitSet(x);
        return Math.min(n, max);
    }

    protected int lowestBitSet(int x)
    {
        if (x == 0)
        {
            return 32;
        }

        int n = 0;
        while ((x & 1) == 0)
        {
            ++n;
            x >>= 1;
        }
        return n;
    }
}
