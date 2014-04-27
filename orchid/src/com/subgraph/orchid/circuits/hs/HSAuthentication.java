package com.subgraph.orchid.circuits.hs;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.circuits.hs.HSDescriptorCookie.CookieType;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorStreamCipher;

public class HSAuthentication {
	private final static int BASIC_ID_LENGTH = 4;
	private final HSDescriptorCookie cookie;
	
	public HSAuthentication(HSDescriptorCookie cookie) {
		this.cookie = cookie;
	}
	
	public byte[] decryptIntroductionPoints(byte[] content) throws HSAuthenticationException {
		final ByteBuffer buffer = ByteBuffer.wrap(content);
		final int firstByte = buffer.get() & 0xFF;
		if(firstByte == 1) {
			return decryptIntroductionPointsWithBasicAuth(buffer);
		} else if(firstByte == 2) {
			return decryptIntroductionPointsWithStealthAuth(buffer);
		} else {
			throw new HSAuthenticationException("Introduction points section begins with unrecognized byte ("+ firstByte +")");
		}
	}
	
	private static class BasicAuthEntry {
		final byte[] id;
		final byte[] skey;
		BasicAuthEntry(byte[] id, byte[] skey) {
			this.id = id;
			this.skey = skey;
		}
	}
	
	private BasicAuthEntry createEntry(ByteBuffer bb) {
		final byte[] id = new byte[BASIC_ID_LENGTH];
		final byte[] skey = new byte[TorStreamCipher.KEY_LEN];
		bb.get(id);
		bb.get(skey);
		return new BasicAuthEntry(id, skey);
	}
	
	private byte[] decryptIntroductionPointsWithBasicAuth(ByteBuffer buffer) throws HSAuthenticationException {
		if(cookie == null || cookie.getType() != CookieType.COOKIE_BASIC) {
			throw new TorParsingException("Introduction points encrypted with 'basic' authentication and no cookie available to decrypt");
		}

		final List<BasicAuthEntry> entries = readBasicEntries(buffer);
		final byte[] iv = readAuthIV(buffer);
		final byte[] id = generateAuthId(iv);
		final byte[] k = findKeyInAuthEntries(entries, id);

		return decryptRemaining(buffer, k, iv);
	}
	
	private List<BasicAuthEntry> readBasicEntries(ByteBuffer b) {
		final int blockCount = b.get() & 0xFF;
		final int entryCount = blockCount * 16;
		final List<BasicAuthEntry> entries = new ArrayList<BasicAuthEntry>(entryCount);
		for(int i = 0; i < entryCount; i++) {
			entries.add( createEntry(b) );
		}
		return entries;
	}
	
	
	private byte[] readAuthIV(ByteBuffer b) {
		final byte[] iv = new byte[16];
		b.get(iv);
		return iv;
	}

	private byte[] generateAuthId(byte[] iv) {
		final TorMessageDigest md = new TorMessageDigest();
		md.update(cookie.getValue());
		md.update(iv);
		final byte[] digest = md.getDigestBytes();
		final byte[] id = new byte[BASIC_ID_LENGTH];
		System.arraycopy(digest, 0, id, 0, BASIC_ID_LENGTH);
		return id;
	}

	private byte[] findKeyInAuthEntries(List<BasicAuthEntry> entries, byte[] id) throws HSAuthenticationException {
		for(BasicAuthEntry e: entries) {
			if(Arrays.equals(id, e.id)) {
				return decryptAuthEntry(e);
			}
		}
		throw new HSAuthenticationException("Could not find matching cookie id for basic authentication");
	}
	
	private byte[] decryptAuthEntry(BasicAuthEntry entry) throws HSAuthenticationException {
		TorStreamCipher cipher = TorStreamCipher.createFromKeyBytes(cookie.getValue());
		cipher.encrypt(entry.skey);
		return entry.skey;
	}
	
	private byte[] decryptRemaining(ByteBuffer buffer, byte[] key, byte[] iv) {
		TorStreamCipher streamCipher = TorStreamCipher.createFromKeyBytesWithIV(key, iv);
		final byte[] remaining = new byte[buffer.remaining()];
		buffer.get(remaining);
		streamCipher.encrypt(remaining);
		return remaining;
	}
	
	private byte[] decryptIntroductionPointsWithStealthAuth(ByteBuffer buffer) {
		if(cookie == null || cookie.getType() != CookieType.COOKIE_STEALTH) {
			throw new TorParsingException("Introduction points encrypted with 'stealth' authentication and no cookie available to descrypt");
		}
		final byte[] iv = readAuthIV(buffer);
		return decryptRemaining(buffer, cookie.getValue(), iv);
	}
}
