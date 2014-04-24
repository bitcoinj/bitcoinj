package com.subgraph.orchid.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.subgraph.orchid.TorException;

public class TorPrivateKey {

	static public TorPrivateKey generateNewKeypair() {
		KeyPairGenerator generator = createGenerator();
		generator.initialize(1024, new SecureRandom());
		KeyPair pair = generator.generateKeyPair();
		return new TorPrivateKey((RSAPrivateKey)pair.getPrivate(), (RSAPublicKey)pair.getPublic());
	}

	static KeyPairGenerator createGenerator() {
		try {
			return KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		}
	}

	private final TorPublicKey publicKey;
	private final RSAPrivateKey privateKey;

	TorPrivateKey(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
		this.privateKey = privateKey;
		this.publicKey = new TorPublicKey(publicKey);
	}

	public TorPublicKey getPublicKey() {
		return publicKey;
	}

	public RSAPublicKey getRSAPublicKey() {
		return publicKey.getRSAPublicKey();
	}

	public RSAPrivateKey getRSAPrivateKey() {
		return privateKey;
	}
}
