package com.subgraph.orchid.crypto;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.data.HexDigest;

/**
 * This class wraps the default cryptographic message digest algorithm
 * used in Tor (SHA-1). 
 */
public class TorMessageDigest {

	
	public static final int TOR_DIGEST_SIZE = 20;
	public static final int TOR_DIGEST256_SIZE = 32;
	
	private static final String TOR_DIGEST_ALGORITHM = "SHA-1";
	private static final String TOR_DIGEST256_ALGORITHM = "SHA-256";

	private final MessageDigest digestInstance;
	private final boolean isDigest256;
	
	public TorMessageDigest(boolean isDigest256) {
		digestInstance = createDigestInstance(isDigest256);
		this.isDigest256 = isDigest256;
	}

	public TorMessageDigest() {
		this(false);
	}

	private MessageDigest createDigestInstance(boolean isDigest256) {
		try {
			final String algorithm = (isDigest256) ? TOR_DIGEST256_ALGORITHM : TOR_DIGEST_ALGORITHM;
			return MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		}
	}

	/**
	 * Return <tt>true</tt> if this is a 256 bit digest instance.
	 * 
	 * @return <tt>true</tt> if this is a 256 bit digest instance.
	 */
	public boolean isDigest256() {
		return isDigest256;
	}

	/**
	 * Return the digest value of all data processed up until this point.
	 * @return The digest value as an array of <code>TOR_DIGEST_SIZE<code> or <code>TOR_DIGEST256_SIZE</code> bytes.
	 */
	public byte[] getDigestBytes() {
		try {
			// Make a clone because #digest() will reset the MessageDigest instance
			// and we want to be able to use this class for running digests on circuits
			final MessageDigest clone = (MessageDigest) digestInstance.clone();
			return clone.digest();
		} catch (CloneNotSupportedException e) {
			throw new TorException(e);
		}
	}

	/**
	 * Return what the digest for the current running hash would be IF we
	 * added <code>data</code>, but don't really add the data to the digest
	 * calculation.
	 */
	public byte[] peekDigest(byte[] data, int offset, int length) {
		try {
			final MessageDigest clone = (MessageDigest) digestInstance.clone();
			clone.update(data, offset, length);
			return clone.digest();
		} catch (CloneNotSupportedException e) {
			throw new TorException(e);
		}
	}

	/**
	 * Calculate the digest value of all data processed up until this point and convert
	 * the digest into a <code>HexDigest</code> object.
	 * @return A new <code>HexDigest</code> object representing the current digest value.
	 * @see HexDigest
	 */
	public HexDigest getHexDigest() {
		return HexDigest.createFromDigestBytes(getDigestBytes());
	}

	/**
	 * Add the entire contents of the byte array <code>input</code> to the current digest calculation.
	 * 
	 * @param input An array of input bytes to process.
	 */
	public void update(byte[] input) {
		digestInstance.update(input);
	}

	/**
	 * Add <code>length</code> bytes of the contents of the byte array <code>input</code> beginning at 
	 * <code>offset</code> into the array to the current digest calculation.
	 * 
	 * @param input An array of input bytes to process.
	 * @param offset The offset into the <code>input</code> array to begin processing.
	 * @param length A count of how many bytes of the <code>input</code> array to process.
	 */
	public void update(byte[] input, int offset, int length) {
		digestInstance.update(input, offset, length);
	}

	/**
	 * Convert the String <code>input</code> into an array of bytes using the ISO-8859-1 encoding
	 * and add these bytes to the current digest calculation.
	 * 
	 * @param input A string to process.
	 */
	public void update(String input) {
		try {
			digestInstance.update(input.getBytes("ISO-8859-1"));
		} catch (UnsupportedEncodingException e) {
			throw new TorException(e);
		}
	}

}
