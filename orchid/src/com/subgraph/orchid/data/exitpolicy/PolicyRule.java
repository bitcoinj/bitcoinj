package com.subgraph.orchid.data.exitpolicy;

import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.data.IPv4Address;

public class PolicyRule {
	private final static String WILDCARD = "*";
	
	public static PolicyRule createAcceptFromString(String rule) {
		return createRule(rule, true);
	}

	public static PolicyRule createRejectFromString(String rule) {
		return createRule(rule, false);
	}

	private static PolicyRule createRule(String rule, boolean isAccept) {
		final String[] args = rule.split(":");
		if(args.length != 2)
			throw new TorParsingException("Could not parse exit policy rule: "+ rule);

		return new PolicyRule(parseNetwork(args[0]), parsePortRange(args[1]), isAccept);
	}

	private static Network parseNetwork(String network) {
		if(network.equals(WILDCARD))
			return Network.ALL_ADDRESSES;
		else
			return Network.createFromString(network);
	}

	private static PortRange parsePortRange(String portRange) {
		if(portRange.equals(WILDCARD))
			return PortRange.ALL_PORTS;
		else
			return PortRange.createFromString(portRange);
	}

	private final boolean isAcceptRule;
	private final Network network;
	private final PortRange portRange;

	private PolicyRule(Network network, PortRange portRange, boolean isAccept) {
		this.network = network;
		this.portRange = portRange;
		this.isAcceptRule = isAccept;
	}

	public boolean matchesPort(int port) {
		if(!network.equals(Network.ALL_ADDRESSES))
			return false;
		return portRange.rangeContains(port);
	}

	public boolean matchesDestination(IPv4Address address, int port) {
		if(!network.contains(address))
			return false;
		return portRange.rangeContains(port);
	}

	public boolean isAcceptRule() {
		return isAcceptRule;
	}
	
	public String toString() {
		final String keyword = isAcceptRule ? "accept" : "reject";
		return keyword + " "+ network + ":"+ portRange;
	}
}
