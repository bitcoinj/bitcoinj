package com.subgraph.orchid.circuits;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.subgraph.orchid.dashboard.DashboardRenderable;
import com.subgraph.orchid.dashboard.DashboardRenderer;

public class CircuitPredictor implements DashboardRenderable {

	private final static Integer INTERNAL_CIRCUIT_PORT_VALUE = 0;
	private final static long TIMEOUT_MS = 60 * 60 * 1000; // One hour
	
	private final Map<Integer, Long> portsSeen;
		
	public CircuitPredictor() {
		portsSeen = new HashMap<Integer,Long>();
		addExitPortRequest(80);
		addInternalRequest();
	}
	
	void addExitPortRequest(int port) {
		synchronized (portsSeen) {
			portsSeen.put(port, System.currentTimeMillis());
		}
	}
	
	void addInternalRequest() {
		addExitPortRequest(INTERNAL_CIRCUIT_PORT_VALUE);
	}
	
	
	private boolean isEntryExpired(Entry<Integer, Long> e, long now) {
		return (now - e.getValue()) > TIMEOUT_MS;
	}
	
	private void removeExpiredPorts() {
		final long now = System.currentTimeMillis();
		final Iterator<Entry<Integer, Long>> it = portsSeen.entrySet().iterator();
		while(it.hasNext()) {
			if(isEntryExpired(it.next(), now)) {
				it.remove();
			}
		}
	}
	
	boolean isInternalPredicted() {
		synchronized (portsSeen) {
			removeExpiredPorts();
			return  portsSeen.containsKey(INTERNAL_CIRCUIT_PORT_VALUE);
		}
	}

	Set<Integer> getPredictedPorts() {
		synchronized (portsSeen) {
			removeExpiredPorts();
			final Set<Integer> result = new HashSet<Integer>(portsSeen.keySet());
			result.remove(INTERNAL_CIRCUIT_PORT_VALUE);
			return result;
		}
	}

	List<PredictedPortTarget> getPredictedPortTargets() {
		final List<PredictedPortTarget> targets = new ArrayList<PredictedPortTarget>();
		for(int p: getPredictedPorts()) {
			targets.add(new PredictedPortTarget(p));
		}
		return targets;
	}

	public void dashboardRender(DashboardRenderer renderer, PrintWriter writer, int flags)
			throws IOException {
		
		if((flags & DASHBOARD_PREDICTED_PORTS) == 0) {
			return;
		}
		writer.println("[Predicted Ports] ");
		for(int port : portsSeen.keySet()) {
			writer.write(" "+ port);
			Long lastSeen = portsSeen.get(port);
			if(lastSeen != null) {
				long now = System.currentTimeMillis();
				long ms = now - lastSeen;
				writer.write(" (last seen "+ TimeUnit.MINUTES.convert(ms, TimeUnit.MILLISECONDS) +" minutes ago)");
			}
			writer.println();
		}
		writer.println();
	}
}
