package com.subgraph.orchid.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * A very minimal ASN.1 BER parser which only supports the ASN.1 object types needed
 * for parsing encoded RSA public keys.
 */
public class ASN1Parser {
	
	private final static int ASN1_TAG_SEQUENCE = 16;
	private final static int ASN1_TAG_INTEGER = 2;
	private final static int ASN1_TAG_BITSTRING = 3;
	
	static interface ASN1Object {};
	
	static class ASN1Sequence implements ASN1Object {
		private final List<ASN1Object> items;
		
		ASN1Sequence(List<ASN1Object> items) {
			this.items = items;
		}
		
		List<ASN1Object> getItems() {
			return items;
		}
	}
	
	static class ASN1Integer implements ASN1Object {
		final BigInteger value;
		ASN1Integer(BigInteger value) {
			this.value = value;
		}
		BigInteger getValue() {
			return value;
		}
	}

	
	static class ASN1BitString implements ASN1Object {
		final byte[] bytes;
		
		ASN1BitString(byte[] bytes) {
			this.bytes = bytes;
		}
		
		byte[] getBytes() {
			return bytes;
		}
	}

	/* For object types we don't handle, just stuff the bytes into here */
	static class ASN1Blob extends ASN1BitString {
		ASN1Blob(byte[] bytes) {
			super(bytes);
		}
	}

	ASN1Object parseASN1(ByteBuffer data) {
		final int typeOctet = data.get() & 0xFF;
		final int tag = typeOctet & 0x1F;
		final ByteBuffer objectBuffer = getObjectBuffer(data);
		
		switch(tag) {
		case ASN1_TAG_SEQUENCE:
			return parseASN1Sequence(objectBuffer);
		case ASN1_TAG_INTEGER:
			return parseASN1Integer(objectBuffer);
		case ASN1_TAG_BITSTRING:
			return parseASN1BitString(objectBuffer);
		default:
			return createBlob(objectBuffer);
		}
		
	}
	
	/*
	 * Read 'length' from data buffer, create a new buffer as a slice() which
	 * contains 'length' bytes of data following length field and return this
	 * buffer. Increment position pointer of data buffer to skip over these bytes.
	 */
	ByteBuffer getObjectBuffer(ByteBuffer data) {
		final int length = parseASN1Length(data);
		if(length > data.remaining()) {
			throw new IllegalArgumentException();
		}
		final ByteBuffer objectBuffer = data.slice();
		objectBuffer.limit(length);
		data.position(data.position() + length);
		return objectBuffer;
	}
	
	int parseASN1Length(ByteBuffer data) {
		final int firstOctet = data.get() & 0xFF;
		if(firstOctet < 0x80) {
			return firstOctet;
		}
		return parseASN1LengthLong(firstOctet & 0x7F, data);
	}
	
	int parseASN1LengthLong(int lengthOctets, ByteBuffer data) {
		if(lengthOctets == 0 || lengthOctets > 3) {
			// indefinite form or too long
			throw new IllegalArgumentException();
		}
		int length = 0;
		for(int i = 0; i < lengthOctets; i++) {
			length <<= 8;
			length |= (data.get() & 0xFF);
		}
		return length;
	}
	
	ASN1Sequence parseASN1Sequence(ByteBuffer data) {
		final List<ASN1Object> obs = new ArrayList<ASN1Object>();
		while(data.hasRemaining()) {
			obs.add(parseASN1(data));
		}
		return new ASN1Sequence(obs);
	}
	
	ASN1Integer parseASN1Integer(ByteBuffer data) {
		return new ASN1Integer(new BigInteger(getRemainingBytes(data)));
	}
	
	ASN1BitString parseASN1BitString(ByteBuffer data) {
		final int unusedBits = data.get() & 0xFF;
		if(unusedBits != 0) {
			throw new IllegalArgumentException();
		}
		return new ASN1BitString(getRemainingBytes(data));
	}

	ASN1Blob createBlob(ByteBuffer data) {
		return new ASN1Blob(getRemainingBytes(data));
	}
	
	private byte[] getRemainingBytes(ByteBuffer data) {
		final byte[] bs = new byte[data.remaining()];
		data.get(bs);
		return bs;
	}
}
