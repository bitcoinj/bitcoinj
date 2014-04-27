package com.subgraph.orchid.crypto;

import java.nio.ByteBuffer;

public class TorKeyDerivation {
	
	private final byte[] kdfBuffer;
	private int round;
	
	public TorKeyDerivation(byte[] seed) {
		this.kdfBuffer = new byte[seed.length + 1];
		System.arraycopy(seed, 0, kdfBuffer, 0, seed.length);
	}
	public void deriveKeys(byte[] keyMaterialOut, byte[] verifyHashOut) {
		final ByteBuffer keyData = deriveKeys(keyMaterialOut.length + verifyHashOut.length);
		keyData.get(verifyHashOut);
		keyData.get(keyMaterialOut);
	}
	
	public ByteBuffer deriveKeys(int length) {
		final ByteBuffer outputBuffer = ByteBuffer.allocate(length);
		round = 0;
		while(outputBuffer.hasRemaining()) {
			byte[] bs = calculateRoundData();
			int n = Math.min(outputBuffer.remaining(), bs.length);
			outputBuffer.put(bs, 0, n);
		}
		
		outputBuffer.flip();
		return outputBuffer;
	}
	
	private byte[] calculateRoundData() {
		final TorMessageDigest md = new TorMessageDigest();
		kdfBuffer[kdfBuffer.length - 1] = (byte) round;
		round += 1;
		md.update(kdfBuffer);
		return md.getDigestBytes();
	}
}
