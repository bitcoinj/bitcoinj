package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Chacha20Poly1305 implements TlsCipher
{
    protected TlsContext context;

    protected ChaChaEngine encryptCipher;
    protected ChaChaEngine decryptCipher;

    public Chacha20Poly1305(TlsContext context) throws IOException
    {
        if (!TlsUtils.isTLSv12(context))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.context = context;

        byte[] key_block = TlsUtils.calculateKeyBlock(context, 64);

        KeyParameter client_write_key = new KeyParameter(key_block, 0, 32);
        KeyParameter server_write_key = new KeyParameter(key_block, 32, 32);

        this.encryptCipher = new ChaChaEngine(20);
        this.decryptCipher = new ChaChaEngine(20);

        KeyParameter encryptKey, decryptKey;
        if (context.isServer())
        {
            encryptKey = server_write_key;
            decryptKey = client_write_key;
        }
        else
        {
            encryptKey = client_write_key;
            decryptKey = server_write_key;
        }

        byte[] dummyNonce = new byte[8];

        this.encryptCipher.init(true, new ParametersWithIV(encryptKey, dummyNonce));
        this.decryptCipher.init(false, new ParametersWithIV(decryptKey, dummyNonce));
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - 16;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len) throws IOException
    {
        int ciphertextLength = len + 16;

        KeyParameter macKey = initRecordMAC(encryptCipher, true, seqNo);

        byte[] output = new byte[ciphertextLength];
        encryptCipher.processBytes(plaintext, offset, len, output, 0);

        byte[] additionalData = getAdditionalData(seqNo, type, len);
        byte[] mac = calculateRecordMAC(macKey, additionalData, output, 0, len);
        System.arraycopy(mac, 0, output, len, mac.length);

        return output;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len) throws IOException
    {
        if (getPlaintextLimit(len) < 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int plaintextLength = len - 16;

        byte[] receivedMAC = Arrays.copyOfRange(ciphertext, offset + plaintextLength, offset + len);

        KeyParameter macKey = initRecordMAC(decryptCipher, false, seqNo);

        byte[] additionalData = getAdditionalData(seqNo, type, plaintextLength);
        byte[] calculatedMAC = calculateRecordMAC(macKey, additionalData, ciphertext, offset, plaintextLength);

        if (!Arrays.constantTimeAreEqual(calculatedMAC, receivedMAC))
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        byte[] output = new byte[plaintextLength];
        decryptCipher.processBytes(ciphertext, offset, plaintextLength, output, 0);

        return output;
    }

    protected KeyParameter initRecordMAC(ChaChaEngine cipher, boolean forEncryption, long seqNo)
    {
        byte[] nonce = new byte[8];
        TlsUtils.writeUint64(seqNo, nonce, 0);

        cipher.init(forEncryption, new ParametersWithIV(null, nonce));

        byte[] firstBlock = new byte[64];
        cipher.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0);

        // NOTE: The BC implementation puts 'r' after 'k'
        System.arraycopy(firstBlock, 0, firstBlock, 32, 16);
        KeyParameter macKey = new KeyParameter(firstBlock, 16, 32);
        Poly1305KeyGenerator.clamp(macKey.getKey());
        return macKey;
    }

    protected byte[] calculateRecordMAC(KeyParameter macKey, byte[] additionalData, byte[] buf, int off, int len)
    {
        Mac mac = new Poly1305();
        mac.init(macKey);

        updateRecordMAC(mac, additionalData, 0, additionalData.length);
        updateRecordMAC(mac, buf, off, len);

        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);
        return output;
    }

    protected void updateRecordMAC(Mac mac, byte[] buf, int off, int len)
    {
        mac.update(buf, off, len);

        byte[] longLen = Pack.longToLittleEndian(len & 0xFFFFFFFFL);
        mac.update(longLen, 0, longLen.length);
    }

    protected byte[] getAdditionalData(long seqNo, short type, int len) throws IOException
    {
        /*
         * additional_data = seq_num + TLSCompressed.type + TLSCompressed.version +
         * TLSCompressed.length
         */
        byte[] additional_data = new byte[13];
        TlsUtils.writeUint64(seqNo, additional_data, 0);
        TlsUtils.writeUint8(type, additional_data, 8);
        TlsUtils.writeVersion(context.getServerVersion(), additional_data, 9);
        TlsUtils.writeUint16(len, additional_data, 11);

        return additional_data;
    }
}
