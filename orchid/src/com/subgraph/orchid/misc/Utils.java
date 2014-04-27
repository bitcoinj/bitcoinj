package com.subgraph.orchid.misc;

public class Utils {
	public static boolean constantTimeArrayEquals(byte[] a1, byte[] a2) {
		if(a1.length != a2.length) {
			return false;
		}
		int result = 0;
		for(int i = 0; i < a1.length; i++) {
			result += (a1[i] & 0xFF) ^ (a2[i] & 0xFF);
		}
		return result == 0;
	}
}
