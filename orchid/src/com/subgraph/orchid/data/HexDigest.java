package com.subgraph.orchid.data;

import java.util.Arrays;
import java.util.List;

import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.encoders.Base64;
import com.subgraph.orchid.encoders.Hex;

/**
 * This class represents both digests and fingerprints that appear in directory
 * documents.  The names fingerprint and digest are used interchangeably in 
 * the specification but generally a fingerprint is a message digest (ie: SHA1)
 * over the DER ASN.1 encoding of a public key.  A digest is usually
 * a message digest over a set of fields in a directory document.
 * 
 * Digests always appear as a 40 character hex string:
 * 
 * 0EA20CAA3CE696E561BC08B15E00106700E8F682
 *
 * Fingerprints may either appear as a single hex string as above or sometimes in
 * a more easily human-parsed spaced format:
 * 
 * 1E0F 5874 2268 E82F C600 D81D 9064 07C5 7CC2 C3A7
 *
 */
public class HexDigest {
	public static HexDigest createFromStringList(List<String> strings) {
		StringBuilder builder = new StringBuilder();
		for(String chunk: strings) 
			builder.append(chunk);
		return createFromString(builder.toString());
	}

	public static HexDigest createFromBase32String(String b32) {
		return new HexDigest(Base32.base32Decode(b32));
	}

	public static HexDigest createFromString(String fingerprint) {
		final String[] parts = fingerprint.split(" ");
		if(parts.length > 1)
			return createFromStringList(Arrays.asList(parts));
		final byte[] digestData = Hex.decode(fingerprint);
		return new HexDigest(digestData);
	}

	public static HexDigest createFromDigestBytes(byte[] data) {
		return new HexDigest(data);
	}
	
	public static HexDigest createDigestForData(byte[] data) {
		final TorMessageDigest digest = new TorMessageDigest();
		digest.update(data);
		return new HexDigest(digest.getDigestBytes());
	}

	private final byte[] digestBytes;
	private final boolean isDigest256;

	private HexDigest(byte[] data) {
		if(data.length != TorMessageDigest.TOR_DIGEST_SIZE && data.length != TorMessageDigest.TOR_DIGEST256_SIZE) {
			throw new TorException("Digest data is not the correct length "+ data.length +" != (" + TorMessageDigest.TOR_DIGEST_SIZE + " or "+ TorMessageDigest.TOR_DIGEST256_SIZE +")");
		}
		digestBytes = new byte[data.length];
		isDigest256 = digestBytes.length == TorMessageDigest.TOR_DIGEST256_SIZE;
		System.arraycopy(data, 0, digestBytes, 0, data.length);
	}

	public boolean isDigest256() {
		return isDigest256;
	}

	public byte[] getRawBytes() {
		return Arrays.copyOf(digestBytes, digestBytes.length);
	}

	public String toString() {
		return new String(Hex.encode(digestBytes));
	}

	/**
	 * Return a spaced fingerprint representation of this HexDigest. 
	 * 
	 * ex:
	 * 
	 * 1E0F 5874 2268 E82F C600 D81D 9064 07C5 7CC2 C3A7
	 *
	 * @return A string representation of this HexDigest in the spaced fingerprint format.
	 */
	public String toSpacedString() {
		final String original = toString();
		final StringBuilder builder = new StringBuilder();
		for(int i = 0; i < original.length(); i++) {
			if(i > 0 && (i % 4) == 0)
				builder.append(' ');
			builder.append(original.charAt(i));
		}
		return builder.toString();
	}

	public String toBase32() {
		return Base32.base32Encode(digestBytes);
	}

	public String toBase64(boolean stripTrailingEquals) {
		final String b64 = new String(Base64.encode(digestBytes), Tor.getDefaultCharset());
		if(stripTrailingEquals) {
			return stripTrailingEquals(b64);
		} else {
			return b64;
		}
	}
		
	private String stripTrailingEquals(String s) {
		int idx = s.length();
		while(idx > 0 && s.charAt(idx - 1) == '=') {
			idx -= 1;
		}
		return s.substring(0, idx);
	}

	public boolean equals(Object o) {
		if(!(o instanceof HexDigest))
			return false;
		final HexDigest other = (HexDigest)o;
		return Arrays.equals(other.digestBytes, this.digestBytes);
	}

	public int hashCode() {
		int hash = 0;
		for(int i = 0; i < 4; i++) {
			hash <<= 8;
			hash |= (digestBytes[i] & 0xFF);
		}
		return hash;
	}

}
