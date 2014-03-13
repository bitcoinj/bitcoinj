package com.subgraph.orchid.circuits.path;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

/**
 * Implements configuration options:
 * 
 *   ExcludeNodes,ExcludeExitNodes,ExitNodes,EntryNodes
 *
 */
public class ConfigNodeFilter implements RouterFilter {

	private final static Pattern NETMASK_PATTERN = Pattern.compile("^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)/(\\d+)$");
	private final static Pattern ADDRESS_BITS_PATTERN = Pattern.compile("^(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+)$");
	
	private final static Pattern IDENTITY_PATTERN = Pattern.compile("^[A-Fa-f0-9]{40}$");
	private final static Pattern COUNTRYCODE_PATTERN = Pattern.compile("^\\{([A-Za-z]{2})\\}$");
	private final static Pattern ROUTERNAME_PATTERN = Pattern.compile("^\\w{1,19}$");

	static class MaskFilter implements RouterFilter {

		private final int network;
		private final int bits;
		private final int mask;
		

		static int createMask(final int maskBitCount) {
			return maskBitCount == 0 ? 0 : (1 << 31) >> (maskBitCount - 1);
		}

		MaskFilter(IPv4Address network, int bits) {
			this.bits = bits;
			this.mask = createMask(bits);
			this.network = network.getAddressData() & mask;
		}
		
		public boolean filter(Router router) {
			final int routerAddress = router.getAddress().getAddressData();
			return (routerAddress & mask) == network;
		}
		
		public String toString() {
			IPv4Address a = new IPv4Address(network);
			return a.toString() + "/" + bits;
			
		}
	}
	
	static class IdentityFilter implements RouterFilter {
		private final HexDigest identity;
		IdentityFilter(HexDigest identity) {
			this.identity = identity;
		}
		public boolean filter(Router router) {
			return router.getIdentityHash().equals(identity);
		}
	}

	static class NameFilter implements RouterFilter {
		private final String name;
		NameFilter(String name) {
			this.name = name;
		}
		public boolean filter(Router router) {
			return name.equals(router.getNickname());
		}
	}
	
	static class CountryCodeFilter implements RouterFilter {
		private final String countryCode;
		public CountryCodeFilter(String countryCode) {
			this.countryCode = countryCode;
		}
		public boolean filter(Router router) {
			return countryCode.equalsIgnoreCase(router.getCountryCode());
		}
	}
	
	static boolean isAddressString(String s) {
		Matcher matcher = NETMASK_PATTERN.matcher(s);
		if(!matcher.matches()) {
			return false;
		}
		try {
			for(int i = 1; i < 5; i++) {
				if(!isValidOctetString(matcher.group(i))) {
					return false;
				}
			}
			return isValidMaskValue(matcher.group(5));
		} catch (NumberFormatException e) {
			return false;
		}
	}
	
	private static boolean isValidOctetString(String s) {
		int n = Integer.parseInt(s);
		return n >= 0 && n <= 255;
	}
	
	private static boolean isValidMaskValue(String s) {
		int n = Integer.parseInt(s);
		return n > 0 && n <= 32;
	}
	
	static boolean isIdentityString(String s) {
		return IDENTITY_PATTERN.matcher(s).matches();
	}
	
	static boolean isCountryCodeString(String s) {
		return COUNTRYCODE_PATTERN.matcher(s).matches();
	}
	
	static boolean isNameString(String s) {
		return ROUTERNAME_PATTERN.matcher(s).matches();
	}

	static RouterFilter createFilterFor(String s) {
		if(isAddressString(s)) {
			return createAddressFilter(s);
		} else if(isCountryCodeString(s)) {
			return createCountryCodeFilter(s);
		} else if(isIdentityString(s)) {
			return createIdentityFilter(s);
		} else if (isNameString(s)) {
			return createNameFilter(s);
		} else {
			return null;
		}
	}

	private static RouterFilter createAddressFilter(String s) {
		final Matcher matcher = ADDRESS_BITS_PATTERN.matcher(s);
		if(!matcher.matches()) {
			throw new IllegalArgumentException();
		}
		final IPv4Address network = IPv4Address.createFromString(matcher.group(1));
		final int bits = Integer.parseInt(matcher.group(2));
		return new MaskFilter(network, bits);
	}
	
	private static RouterFilter createIdentityFilter(String s) {
		if(isIdentityString(s)) {
			throw new IllegalArgumentException();
		}
		final HexDigest identity = HexDigest.createFromString(s);
		return new IdentityFilter(identity);
	}
	
	private static RouterFilter createCountryCodeFilter(String s) {
		final Matcher matcher = COUNTRYCODE_PATTERN.matcher(s);
		if(!matcher.matches()) {
			throw new IllegalArgumentException();
		}
		return new CountryCodeFilter(matcher.group(1));
	}
	
	private static RouterFilter createNameFilter(String s) {
		if(!isNameString(s)) {
			throw new IllegalArgumentException();
		}
		return new NameFilter(s);
	}

	static ConfigNodeFilter createFromStrings(List<String> stringList) {
		final List<RouterFilter> filters = new ArrayList<RouterFilter>();
		for(String s: stringList) {
			RouterFilter f = createFilterFor(s);
			if(f != null) {
				filters.add(f);
			}
		}
		return new ConfigNodeFilter(filters);
	}

	private final List<RouterFilter> filterList;
	
	private ConfigNodeFilter(List<RouterFilter> filterList) {
		this.filterList = filterList;
	}

	public boolean filter(Router router) {
		for(RouterFilter f: filterList) {
			if(f.filter(router)) {
				return true;
			}
		}
		return false;
	}
	
	boolean isEmpty() {
		return filterList.isEmpty();
	}
}
