package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class TlsAEADCipher
    implements TlsCipher
{
    protected TlsContext context;
    protected int macSize;
    protected int nonce_explicit_length;

    protected AEADBlockCipher encryptCipher;
    protected AEADBlockCipher decryptCipher;

    protected byte[] encryptImplicitNonce, decryptImplicitNonce;

    public TlsAEADCipher(TlsContext context, AEADBlockCipher clientWriteCipher, AEADBlockCipher serverWriteCipher,
        int cipherKeySize, int macSize) throws IOException
    {
        if (!TlsUtils.isTLSv12(context))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.context = context;
        this.macSize = macSize;

        // NOTE: Valid for RFC 5288/6655 ciphers but may need review for other AEAD ciphers
        this.nonce_explicit_length = 8;

        // TODO SecurityParameters.fixed_iv_length
        int fixed_iv_length = 4;

        int key_block_size = (2 * cipherKeySize) + (2 * fixed_iv_length);

        byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        KeyParameter client_write_key = new KeyParameter(key_block, offset, cipherKeySize);
        offset += cipherKeySize;
        KeyParameter server_write_key = new KeyParameter(key_block, offset, cipherKeySize);
        offset += cipherKeySize;
        byte[] client_write_IV = Arrays.copyOfRange(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;
        byte[] server_write_IV = Arrays.copyOfRange(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        KeyParameter encryptKey, decryptKey;
        if (context.isServer())
        {
            this.encryptCipher = serverWriteCipher;
            this.decryptCipher = clientWriteCipher;
            this.encryptImplicitNonce = server_write_IV;
            this.decryptImplicitNonce = client_write_IV;
            encryptKey = server_write_key;
            decryptKey = client_write_key;
        }
        else
        {
            this.encryptCipher = clientWriteCipher;
            this.decryptCipher = serverWriteCipher;
            this.encryptImplicitNonce = client_write_IV;
            this.decryptImplicitNonce = server_write_IV;
            encryptKey = client_write_key;
            decryptKey = server_write_key;
        }

        byte[] dummyNonce = new byte[fixed_iv_length + nonce_explicit_length];

        this.encryptCipher.init(true, new AEADParameters(encryptKey, 8 * macSize, dummyNonce));
        this.decryptCipher.init(false, new AEADParameters(decryptKey, 8 * macSize, dummyNonce));
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        // TODO We ought to be able to ask the decryptCipher (independently of it's current state!)
        return ciphertextLimit - macSize - nonce_explicit_length;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException
    {
        byte[] nonce = new byte[this.encryptImplicitNonce.length + nonce_explicit_length];
        System.arraycopy(encryptImplicitNonce, 0, nonce, 0, encryptImplicitNonce.length);

        /*
         * RFC 5288/6655 The nonce_explicit MAY be the 64-bit sequence number.
         * 
         * (May need review for other AEAD ciphers).
         */
        TlsUtils.writeUint64(seqNo, nonce, encryptImplicitNonce.length);

        int plaintextOffset = offset;
        int plaintextLength = len;
        int ciphertextLength = encryptCipher.getOutputSize(plaintextLength);

        byte[] output = new byte[nonce_explicit_length + ciphertextLength];
        System.arraycopy(nonce, encryptImplicitNonce.length, output, 0, nonce_explicit_length);
        int outputPos = nonce_explicit_length;

        byte[] additionalData = getAdditionalData(seqNo, type, plaintextLength);
        AEADParameters parameters = new AEADParameters(null, 8 * macSize, nonce, additionalData);

        try
        {
            encryptCipher.init(true, parameters);
            outputPos += encryptCipher.processBytes(plaintext, plaintextOffset, plaintextLength, output, outputPos);
            outputPos += encryptCipher.doFinal(output, outputPos);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (outputPos != output.length)
        {
            // NOTE: Existing AEAD cipher implementations all give exact output lengths
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return output;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        if (getPlaintextLimit(len) < 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        byte[] nonce = new byte[this.decryptImplicitNonce.length + nonce_explicit_length];
        System.arraycopy(decryptImplicitNonce, 0, nonce, 0, decryptImplicitNonce.length);
        System.arraycopy(ciphertext, offset, nonce, decryptImplicitNonce.length, nonce_explicit_length);

        int ciphertextOffset = offset + nonce_explicit_length;
        int ciphertextLength = len - nonce_explicit_length;
        int plaintextLength = decryptCipher.getOutputSize(ciphertextLength);

        byte[] output = new byte[plaintextLength];
        int outputPos = 0;

        byte[] additionalData = getAdditionalData(seqNo, type, plaintextLength);
        AEADParameters parameters = new AEADParameters(null, 8 * macSize, nonce, additionalData);

        try
        {
            decryptCipher.init(false, parameters);
            outputPos += decryptCipher.processBytes(ciphertext, ciphertextOffset, ciphertextLength, output, outputPos);
            outputPos += decryptCipher.doFinal(output, outputPos);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        if (outputPos != output.length)
        {
            // NOTE: Existing AEAD cipher implementations all give exact output lengths
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return output;
    }

    protected byte[] getAdditionalData(long seqNo, short type, int len)
        throws IOException
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
