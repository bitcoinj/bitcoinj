package com.subgraph.orchid.crypto;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class TorCreateFastKeyAgreement implements TorKeyAgreement {
	
	private final byte[] xValue;
	private byte[] yValue;

	public TorCreateFastKeyAgreement() {
		final TorRandom random = new TorRandom();
		xValue = random.getBytes(TorMessageDigest.TOR_DIGEST_SIZE);
	}
	
	public byte[] getPublicValue() {
		return Arrays.copyOf(xValue, xValue.length);
	}

	public void setOtherValue(byte[] yValue) {
		if(yValue == null || yValue.length != TorMessageDigest.TOR_DIGEST_SIZE) {
			throw new IllegalArgumentException();
		}
		this.yValue = Arrays.copyOf(yValue, yValue.length);
	}
	
	public byte[] getDerivedValue() {
		if(yValue == null) {
			throw new IllegalStateException("Must call setOtherValue() first");
		}
		final byte[] result = new byte[2 * TorMessageDigest.TOR_DIGEST_SIZE];
		System.arraycopy(xValue, 0, result, 0, TorMessageDigest.TOR_DIGEST_SIZE);
		System.arraycopy(yValue, 0, result, TorMessageDigest.TOR_DIGEST_SIZE, TorMessageDigest.TOR_DIGEST_SIZE);
		return result;
	}

	public byte[] createOnionSkin() {
		return getPublicValue();
	}

	public boolean deriveKeysFromHandshakeResponse(byte[] handshakeResponse,
			byte[] keyMaterialOut, byte[] verifyHashOut) {
		final ByteBuffer bb = ByteBuffer.wrap(handshakeResponse);
		final byte[] peerValue = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
		final byte[] keyHash = new byte[TorMessageDigest.TOR_DIGEST_SIZE];
		bb.get(peerValue);
		bb.get(keyHash);
		setOtherValue(peerValue);
		final byte[] seed = getDerivedValue();
		final TorKeyDerivation kdf = new TorKeyDerivation(seed);
		kdf.deriveKeys(keyMaterialOut, verifyHashOut);
		return Arrays.equals(verifyHashOut, keyHash);
	}
}
