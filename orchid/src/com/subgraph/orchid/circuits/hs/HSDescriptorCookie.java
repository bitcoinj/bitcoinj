package com.subgraph.orchid.circuits.hs;

public class HSDescriptorCookie {

	public enum CookieType { COOKIE_BASIC, COOKIE_STEALTH };

	private final CookieType type;
	private final byte[] value;
	
	public HSDescriptorCookie(CookieType type, byte[] value) {
		this.type = type;
		this.value = value;
	}
	
	public byte getAuthTypeByte() {
		switch(type) {
		case COOKIE_BASIC:
			return 1;
		case COOKIE_STEALTH:
			return 2;
		default:
			throw new IllegalStateException();
		}
	}

	public CookieType getType() {
		return type;
	}

	public byte[] getValue() {
		return value;
	}
}
