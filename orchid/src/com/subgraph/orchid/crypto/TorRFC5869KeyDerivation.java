package com.subgraph.orchid.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.subgraph.orchid.Tor;

public class TorRFC5869KeyDerivation {
	private final static String PROTOID = "ntor-curve25519-sha256-1";
	private final static String M_EXPAND = PROTOID + ":key_expand";
	private final static byte[] M_EXPAND_BYTES = M_EXPAND.getBytes(Tor.getDefaultCharset());
	
	private final byte[] seed;
	
	public TorRFC5869KeyDerivation(byte[] seed) {
		this.seed = new byte[seed.length];
		System.arraycopy(seed, 0, this.seed, 0, seed.length);
	}
	
	public void deriveKeys(byte[] keyMaterialOut, byte[] verifyHashOut) {
		final ByteBuffer keyData = deriveKeys(keyMaterialOut.length + verifyHashOut.length);
		keyData.get(keyMaterialOut);
		keyData.get(verifyHashOut);
	}
	
	public ByteBuffer deriveKeys(int length) {
		int round = 1;
		final ByteBuffer bb = makeBuffer(length);
		byte[] macOutput = null;
		while(bb.hasRemaining()) {
			macOutput = expandRound(round, macOutput);
			if(macOutput.length > bb.remaining()) {
				bb.put(macOutput, 0, bb.remaining());
			} else {
				bb.put(macOutput);
			}
			round += 1;
		}
		bb.flip();
		return bb;
	}
	
	private byte[] expandRound(int round, byte[] priorMac) {
		final ByteBuffer bb;
		if(round == 1) {
			bb = makeBuffer(M_EXPAND_BYTES.length + 1);
		} else {
			bb = makeBuffer(M_EXPAND_BYTES.length + TorMessageDigest.TOR_DIGEST256_SIZE + 1);
			bb.put(priorMac);
		}
		bb.put(M_EXPAND_BYTES);
		bb.put((byte) round);

		final Mac mac = createMacInstance();
		return mac.doFinal(bb.array());
	}
	
	private ByteBuffer makeBuffer(int len) {
		final byte[] bs = new byte[len];
		return ByteBuffer.wrap(bs);
	}

	private Mac createMacInstance() {
		final SecretKeySpec keyspec = new SecretKeySpec(seed, "HmacSHA256");
		try {
			final Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(keyspec);
			return mac;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Could not create HmacSHA256 instance: "+ e);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException("Could not create HmacSHA256 instance: "+ e);
		}
	}
}
