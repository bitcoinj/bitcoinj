package com.subgraph.orchid.data.exitpolicy;

import java.util.ArrayList;
import java.util.List;


/**
 * Used by router status entries in consensus documents
 */
public class ExitPorts {
	public static ExitPorts createAcceptExitPorts(String ports) {
		final ExitPorts exitPorts = new ExitPorts(true);
		exitPorts.parsePortRanges(ports);
		return exitPorts;
	}
	
	public static ExitPorts createRejectExitPorts(String ports) {
		final ExitPorts exitPorts = new ExitPorts(false);
		exitPorts.parsePortRanges(ports);
		return exitPorts;
	}
	
	private final List<PortRange> ranges = new ArrayList<PortRange>();
	private final boolean areAcceptPorts;
	
	private ExitPorts(boolean acceptPorts) {
		this.areAcceptPorts = acceptPorts;
	}
	
	public boolean areAcceptPorts() {
		return areAcceptPorts;
	}
	
	public boolean acceptsPort(int port) {
		if(areAcceptPorts) 
			return contains(port);
		else
			return !contains(port);
	}
	public boolean contains(int port) {
		for(PortRange r: ranges) 
			if(r.rangeContains(port))
				return true;
		return false;
	}
	
	private void parsePortRanges(String portRanges) {
		final String[] args = portRanges.split(",");
		for(String arg: args)
			ranges.add(PortRange.createFromString(arg));
	}
	

}
