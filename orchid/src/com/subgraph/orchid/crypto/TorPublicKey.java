package com.subgraph.orchid.crypto;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.misc.Utils;

/**
 * This class wraps the RSA public keys used in the Tor protocol.
 */
public class TorPublicKey {
	static public TorPublicKey createFromPEMBuffer(String buffer) {
		return new TorPublicKey(buffer);
	}

	private final String pemBuffer;
	private RSAPublicKey key;

	private byte[] rawKeyBytes = null;
	private HexDigest keyFingerprint = null;

	private TorPublicKey(String pemBuffer) {
		this.pemBuffer = pemBuffer;
		this.key = null;
	}

	public TorPublicKey(RSAPublicKey key) {
		this.pemBuffer = null;
		this.key = key;
	}

	private synchronized RSAPublicKey getKey() {
		if(key != null) {
			return key;
		} else if(pemBuffer != null) {
			final RSAKeyEncoder encoder = new RSAKeyEncoder();
			try {
				key = encoder.parsePEMPublicKey(pemBuffer);
			} catch (GeneralSecurityException e) {
				throw new IllegalArgumentException("Failed to parse PEM encoded key: "+ e);
			}
		}
		return key;
	}

	public synchronized byte[] getRawBytes() {
		if(rawKeyBytes == null) {
			final RSAKeyEncoder encoder = new RSAKeyEncoder();
			rawKeyBytes = encoder.getPKCS1Encoded(getKey());
		}
		return rawKeyBytes;
	}

	public synchronized HexDigest getFingerprint() {
		if(keyFingerprint == null) {
			keyFingerprint = HexDigest.createDigestForData(getRawBytes());
		}
		return keyFingerprint;
	}

	public boolean verifySignature(TorSignature signature, HexDigest digest) {
		return verifySignatureFromDigestBytes(signature, digest.getRawBytes());
	}

	public boolean verifySignature(TorSignature signature, TorMessageDigest digest) {
		return verifySignatureFromDigestBytes(signature, digest.getDigestBytes());
	}

	public boolean verifySignatureFromDigestBytes(TorSignature signature, byte[] digestBytes) {
		final Cipher cipher = createCipherInstance();
		try {
			byte[] decrypted = cipher.doFinal(signature.getSignatureBytes());
			return Utils.constantTimeArrayEquals(decrypted, digestBytes);
		} catch (IllegalBlockSizeException e) {
			throw new TorException(e);
		} catch (BadPaddingException e) {
			throw new TorException(e);
		}
	}

	private Cipher createCipherInstance() {
		try {
			Cipher cipher = getCipherInstance();
			cipher.init(Cipher.DECRYPT_MODE, getKey());
			return cipher;
		} catch (InvalidKeyException e) {
			throw new TorException(e);
		} 
	}

	private Cipher getCipherInstance() {
		try {
			try {
				return Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
			} catch (NoSuchProviderException e) {
				return Cipher.getInstance("RSA/ECB/PKCS1Padding");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		} catch (NoSuchPaddingException e) {
			throw new TorException(e);
		}
	}
	
	public RSAPublicKey getRSAPublicKey() {
		return getKey();
	}

	public String toString() {
		return "Tor Public Key: " + getFingerprint();
	}

	public boolean equals(Object o) {
		if(!(o instanceof TorPublicKey))
			return false;
		final TorPublicKey other = (TorPublicKey) o;
		return other.getFingerprint().equals(getFingerprint());
	}

	public int hashCode() {
		return getFingerprint().hashCode();
	}
}
