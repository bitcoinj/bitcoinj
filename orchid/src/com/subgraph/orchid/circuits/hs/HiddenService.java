package com.subgraph.orchid.circuits.hs;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.subgraph.orchid.HiddenServiceCircuit;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.hs.HSDescriptorCookie.CookieType;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.data.Base32;
import com.subgraph.orchid.data.HexDigest;

public class HiddenService {
	
	private final TorConfig config;
	private final byte[] permanentId;

	private HSDescriptor descriptor;
	private HiddenServiceCircuit circuit;
	
	static byte[] decodeOnion(String onionAddress) {
		final int idx = onionAddress.indexOf(".onion");
		if(idx == -1) {
			return Base32.base32Decode(onionAddress);
		} else {
			return Base32.base32Decode(onionAddress.substring(0, idx));
		}
	}
	

	HiddenService(TorConfig config, byte[] permanentId) {
		this.config = config;
		this.permanentId = permanentId;
	}

	String getOnionAddressForLogging() {
		if(config.getSafeLogging()) {
			return "[scrubbed]";
		} else {
			return getOnionAddress();
		}
	}

	String getOnionAddress() {
		return Base32.base32Encode(permanentId) + ".onion";
	}

	boolean hasCurrentDescriptor() {
		return (descriptor != null && !descriptor.isExpired());
	}
	
	HSDescriptor getDescriptor() {
		return descriptor;
	}

	void setDescriptor(HSDescriptor descriptor) {
		this.descriptor = descriptor;
	}

	HiddenServiceCircuit getCircuit() {
		return circuit;
	}
	
	void setCircuit(HiddenServiceCircuit circuit) {
		this.circuit = circuit;
	}
	
	HSDescriptorCookie getAuthenticationCookie() {
		return config.getHidServAuth(getOnionAddress());
	}

	List<HexDigest> getAllCurrentDescriptorIds() {
		final List<HexDigest> ids = new ArrayList<HexDigest>();
		ids.add(getCurrentDescriptorId(0));
		ids.add(getCurrentDescriptorId(1));
		return ids;
	}

	HexDigest getCurrentDescriptorId(int replica) {
		final TorMessageDigest digest = new TorMessageDigest();
		digest.update(permanentId);
		digest.update(getCurrentSecretId(replica));
		return digest.getHexDigest();
	}

	byte[] getCurrentSecretId(int replica) {
		final TorMessageDigest digest = new TorMessageDigest();
		digest.update(getCurrentTimePeriod());
		final HSDescriptorCookie cookie = getAuthenticationCookie();
		if(cookie != null && cookie.getType() == CookieType.COOKIE_STEALTH) {
			digest.update(cookie.getValue());
		}
		digest.update(new byte[] { (byte) replica });
		return digest.getDigestBytes();
	}

	byte[] getCurrentTimePeriod() {
		final long now = System.currentTimeMillis() / 1000;
		final int idByte = permanentId[0] & 0xFF;
		return calculateTimePeriod(now, idByte);
	}

	static byte[] calculateTimePeriod(long currentTime, int idByte) {
		final long t = (currentTime + (idByte * 86400L / 256)) / 86400L;
		return toNetworkBytes(t);
	}
	
	static byte[] toNetworkBytes(long value) {
		final byte[] result = new byte[4];
		for(int i = 3; i >= 0; i--) {
			result[i] = (byte) (value & 0xFF);
			value >>= 8;
		}
		return result;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(permanentId);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		HiddenService other = (HiddenService) obj;
		if (!Arrays.equals(permanentId, other.permanentId))
			return false;
		return true;
	}
}
