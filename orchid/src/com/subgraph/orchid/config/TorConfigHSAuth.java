package com.subgraph.orchid.config;

import java.util.HashMap;
import java.util.Map;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.hs.HSDescriptorCookie;
import com.subgraph.orchid.circuits.hs.HSDescriptorCookie.CookieType;
import com.subgraph.orchid.data.Base32;
import com.subgraph.orchid.encoders.Base64;

public class TorConfigHSAuth {
	
	private final Map<String, HSDescriptorCookie> map = new HashMap<String, HSDescriptorCookie>();

	void add(String key, String b64Value) {
		final HSDescriptorCookie cookie = createFromBase64(b64Value);
		final String k = validateKey(key);
		map.put(k, cookie);
	}
	
	private String validateKey(String key) {
		final String k = (key.endsWith(".onion")) ? key.substring(0, (key.length() - 6)) : key;
		try {
			byte[] decoded = Base32.base32Decode(k);
			if(decoded.length != 10) {
				throw new IllegalArgumentException();
			}
			return k;
		} catch (TorException e) {
			throw new IllegalArgumentException(e.getMessage());
		}
	}
	
	HSDescriptorCookie get(String key) {
		return map.get(validateKey(key));
	}
	
	private HSDescriptorCookie createFromBase64(String b64) {
		if(b64.length() != 22) {
			throw new IllegalArgumentException();
		}
		final byte[] decoded = Base64.decode(b64 + "A=");
		final byte lastByte = decoded[decoded.length - 1];
		final int flag = (lastByte & 0xFF) >> 4;
		final byte[] cookie = new byte[decoded.length - 1];
		System.arraycopy(decoded, 0, cookie, 0, cookie.length);
		switch(flag) {
		case 0:
			return new HSDescriptorCookie(CookieType.COOKIE_BASIC, cookie);
		case 1:
			return new HSDescriptorCookie(CookieType.COOKIE_STEALTH, cookie);
		default:
			throw new TorException("Illegal cookie descriptor with flag value: "+ flag);
		}
	}
}
