package com.subgraph.orchid.data.exitpolicy;

import com.subgraph.orchid.data.IPv4Address;

public interface ExitTarget {
	boolean isAddressTarget();
	IPv4Address getAddress();
	String getHostname();
	int getPort();
}
