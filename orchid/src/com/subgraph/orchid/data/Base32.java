package com.subgraph.orchid.data;

import com.subgraph.orchid.TorException;

public class Base32 {
	private final static String BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567";
	
	public static String base32Encode(byte[] source) {
		return base32Encode(source, 0, source.length);
	}
	
	public static String base32Encode(byte[] source, int offset, int length) {
		final int nbits = length * 8;
		if(nbits % 5 != 0) 
			throw new TorException("Base32 input length must be a multiple of 5 bits");
		
		final int outlen = nbits / 5;
		final StringBuffer outbuffer = new StringBuffer();
		int bit = 0;
		for(int i = 0; i < outlen; i++) {
			int v = (source[bit / 8] & 0xFF) << 8;
			if(bit + 5 < nbits) v += (source[bit / 8 + 1] & 0xFF);
			int u = (v >> (11 - (bit % 8))) & 0x1F;
			outbuffer.append(BASE32_CHARS.charAt(u));
			bit += 5;
		}		
		return outbuffer.toString();
	}
	
	public static byte[] base32Decode(String source) {
		int[] v = stringToIntVector(source);
		
		int nbits = source.length() * 5;
		if(nbits % 8 != 0) 
			throw new TorException("Base32 decoded array must be a muliple of 8 bits");
		
		int outlen = nbits / 8;
		byte[] outbytes = new byte[outlen];
		
		int bit = 0;
		for(int i = 0; i < outlen; i++) {
			int bb = bit / 5;
			outbytes[i] = (byte) decodeByte(bit, v[bb], v[bb + 1], v[bb + 2]);
			bit += 8;	
		}
		return outbytes;
	}
	
	private static int decodeByte(int bitOffset, int b0, int b1, int b2) {
		switch(bitOffset % 40) {
		case 0: 
			return ls(b0, 3) + rs(b1, 2);
		case 8:
			return ls(b0, 6) + ls(b1, 1) + rs (b2, 4);
		case 16:
			return ls(b0, 4) + rs(b1, 1);
		case 24:
			return ls(b0, 7) + ls(b1, 2) + rs(b2, 3);
		case 32:
			return ls(b0, 5) + (b1 & 0xFF);
		}
		throw new TorException("Illegal bit offset");
	}
	
	private static int ls(int n, int shift) {
		return ((n << shift) & 0xFF);
	}
	
	private static int rs(int n, int shift) {
		return ((n >> shift) & 0xFF);
	}
	
	private static int[] stringToIntVector(String s) {
		final int[] ints = new int[s.length() + 1];
		for(int i = 0; i < s.length(); i++) {
			int b = s.charAt(i) & 0xFF;
			if(b > 0x60 && b < 0x7B)
				ints[i] = b - 0x61;
			else if(b > 0x31 && b < 0x38) 
				ints[i] = b - 0x18;
			else if(b > 0x40 && b < 0x5B) 
				ints[i] = b - 0x41;
			else
				throw new TorException("Illegal character in base32 encoded string: "+ s.charAt(i));
		}
		return ints;
	}
}
