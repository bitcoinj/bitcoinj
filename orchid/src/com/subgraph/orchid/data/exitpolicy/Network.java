package com.subgraph.orchid.data.exitpolicy;

import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.data.IPv4Address;

public class Network {
	public static final Network ALL_ADDRESSES = new Network(IPv4Address.createFromString("0.0.0.0"), 0, "*");
	public static Network createFromString(String networkString) {
		final String[] parts = networkString.split("/");
		final IPv4Address network = IPv4Address.createFromString(parts[0]);
		if(parts.length == 1)
			return new Network(network, 32, networkString);
		
		if(parts.length != 2)
			throw new TorParsingException("Invalid network CIDR notation: " + networkString);

		try {
			final int maskBits = Integer.parseInt(parts[1]);
			return new Network(network, maskBits, networkString);
		} catch(NumberFormatException e) {
			throw new TorParsingException("Invalid netblock mask bit value: " + parts[1]);
		}
	}
	
	private final IPv4Address network;
	private final int maskValue;
	private final String originalString;
	
	Network(IPv4Address network, int bits, String originalString) {
		this.network = network;
		this.maskValue = createMask(bits);
		this.originalString = originalString;
	}
	
	private static int createMask(int maskBits) {
		return maskBits == 0 ? 0 : (1 << 31) >> (maskBits - 1);
	}
	
	public boolean contains(IPv4Address address) {
		return (address.getAddressData() & maskValue) == (network.getAddressData() & maskValue);
	}
	
	public String toString() {
		return originalString;
	}

}
