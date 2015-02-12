package com.subgraph.orchid.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.subgraph.orchid.TorException;

/**
 * The <code>HybridEncryption</code> class implements the "hybrid encryption" scheme
 * as described in section 0.3 of the main Tor specification (tor-spec.txt).
 */
public class HybridEncryption {
	
	private final static int PK_ENC_LEN = 128;
	private final static int PK_PAD_LEN = 42;
	private final static int PK_DATA_LEN = PK_ENC_LEN - PK_PAD_LEN; // 86 bytes
	private final static int PK_DATA_LEN_WITH_KEY = PK_DATA_LEN - TorStreamCipher.KEY_LEN; // 70 bytes
	/*
	 * The "hybrid encryption" of a byte sequence M with a public key PK is
   	 * computed as follows:
   	 * 
     *  1. If M is less than PK_ENC_LEN-PK_PAD_LEN (86), pad and encrypt M with PK.
     *  2. Otherwise, generate a KEY_LEN byte random key K.
     *     Let M1 = the first PK_ENC_LEN-PK_PAD_LEN-KEY_LEN (70) bytes of M,
     *     and let M2 = the rest of M.
     *     Pad and encrypt K|M1 with PK.  Encrypt M2 with our stream cipher,
     *     using the key K.  Concatenate these encrypted values.
	 */
	final private Cipher cipher;
	
	/**
	 * Create a new <code>HybridEncryption</code> instance which can be used for performing
	 * "hybrid encryption" operations as described in the main Tor specification (tor-spec.txt).
	 */
	public HybridEncryption() {
		try {
			cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		} catch (NoSuchPaddingException e) {
			throw new TorException(e);
		}
	}
	
	/**
	 * Encrypt the entire contents of the byte array <code>data</code> with the given <code>TorPublicKey</code>
	 * according to the "hybrid encryption" scheme described in the main Tor specification (tor-spec.txt).
	 * 
	 * @param data The bytes to be encrypted.
	 * @param publicKey The public key to use for encryption.
	 * @return A new array containing the encrypted data.
	 */
	public byte[] encrypt(byte[] data, TorPublicKey publicKey) {
		if(data.length < PK_DATA_LEN) 
			return encryptSimple(data, publicKey);
		
		// RSA( K | M1 ) --> C1
		TorStreamCipher randomKeyCipher = TorStreamCipher.createWithRandomKey();
		final byte[] kAndM1 = new byte[PK_DATA_LEN];
		System.arraycopy(randomKeyCipher.getKeyBytes(), 0, kAndM1, 0, TorStreamCipher.KEY_LEN);
		System.arraycopy(data, 0, kAndM1, TorStreamCipher.KEY_LEN, PK_DATA_LEN_WITH_KEY);
		final byte[] c1 = encryptSimple(kAndM1, publicKey);
		
		// AES_CTR(M2)  --> C2
		final byte[] c2 = new byte[data.length - PK_DATA_LEN_WITH_KEY];
		System.arraycopy(data, PK_DATA_LEN_WITH_KEY, c2, 0, c2.length);
		randomKeyCipher.encrypt(c2);
		//final byte[] c2 = randomKeyCipher.doFinal(data, PK_DATA_LEN_WITH_KEY, data.length - PK_DATA_LEN_WITH_KEY);
		
		// C1 | C2
		final byte[] output = new byte[c1.length + c2.length];
		System.arraycopy(c1, 0, output, 0, c1.length);
		System.arraycopy(c2, 0, output, c1.length, c2.length);
		return output;		
	}
	
	private byte[] encryptSimple(byte[] data, TorPublicKey publicKey) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, publicKey.getRSAPublicKey());
			return cipher.doFinal(data);
		} catch (InvalidKeyException e) {
			throw new TorException(e);
		} catch (IllegalBlockSizeException e) {
			throw new TorException(e);
		} catch (BadPaddingException e) {
			throw new TorException(e);
		}
	}
	
	/**
	 * Decrypt the contents of the byte array <code>data</code> with the given <code>TorPrivateKey</code>
	 * according to the "hybrid encryption" scheme described in the main Tor specification (tor-spec.txt).
	 * 
	 * @param data Encrypted data to decrypt.
	 * @param privateKey The private key to use to decrypt the data.
	 * @return A new byte array containing the decrypted data.
	 */
	
	public byte[] decrypt(byte[] data, TorPrivateKey privateKey) {
		if(data.length < PK_ENC_LEN)
			throw new TorException("Message is too short");
		
		if(data.length == PK_ENC_LEN) 
			return decryptSimple(data, privateKey);
		
		// ( C1 | C2 ) --> C1, C2
		final byte[] c1 = new byte[PK_ENC_LEN];
		final byte[] c2 = new byte[data.length - PK_ENC_LEN];
		System.arraycopy(data, 0, c1, 0, PK_ENC_LEN);
		System.arraycopy(data, PK_ENC_LEN, c2, 0, c2.length);
		
		// RSA( C1 ) --> ( K | M1 ) --> K, M1
		final byte[] kAndM1 = decryptSimple(c1, privateKey);
		final byte[] streamKey = new byte[TorStreamCipher.KEY_LEN];
		final int m1Length = kAndM1.length - TorStreamCipher.KEY_LEN;
		final byte[] m1 = new byte[m1Length];
		System.arraycopy(kAndM1, 0, streamKey, 0, TorStreamCipher.KEY_LEN);
		System.arraycopy(kAndM1, TorStreamCipher.KEY_LEN, m1, 0, m1Length);
		
		// AES_CTR( C2 ) --> M2
		final TorStreamCipher streamCipher = TorStreamCipher.createFromKeyBytes(streamKey);
		streamCipher.encrypt(c2);
		final byte[] m2 = c2;
		
		final byte[] output = new byte[m1.length + m2.length];
		System.arraycopy(m1, 0, output, 0, m1.length);
		System.arraycopy(m2, 0, output, m1.length, m2.length);
		return output;		      
	}
	
	private byte[] decryptSimple(byte[] data, TorPrivateKey privateKey) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, privateKey.getRSAPrivateKey());
			return cipher.doFinal(data);
		} catch (InvalidKeyException e) {
			throw new TorException(e);
		} catch (IllegalBlockSizeException e) {
			throw new TorException(e);
		} catch (BadPaddingException e) {
			throw new TorException(e);
		}
	}
	
	
}
