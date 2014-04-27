package com.subgraph.orchid.data.exitpolicy;

import java.util.ArrayList;
import java.util.List;

import com.subgraph.orchid.data.IPv4Address;

public class ExitPolicy {
	private final List<PolicyRule> rules = new ArrayList<PolicyRule>();

	public void addAcceptRule(String rule) {
		rules.add(PolicyRule.createAcceptFromString(rule));
	}

	public void addRejectRule(String rule) {
		rules.add(PolicyRule.createRejectFromString(rule));
	}

	public boolean acceptsTarget(ExitTarget target) {
		if(target.isAddressTarget())
			return acceptsDestination(target.getAddress(), target.getPort());
		else
			return acceptsPort(target.getPort());
	}
	
	public boolean acceptsDestination(IPv4Address address, int port) {
		if(address == null)
			return acceptsPort(port);

		for(PolicyRule r: rules) {
			if(r.matchesDestination(address, port)) 
				return r.isAcceptRule();
		}
		// Default accept (see dir-spec.txt section 2.1, 'accept'/'reject' keywords)
		return true;
	}

	public boolean acceptsPort(int port) {
		for(PolicyRule r: rules) {
			if(r.matchesPort(port))
				return r.isAcceptRule();
		}
		return false;
	}

	public String toString() {
		final StringBuilder sb = new StringBuilder();
		for(PolicyRule r: rules) {
			sb.append(r);
			sb.append("\n");
		}
		return sb.toString();
	}
}
