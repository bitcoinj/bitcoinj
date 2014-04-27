package com.subgraph.orchid.circuits;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.ConnectionFailedException;
import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.ConnectionTimeoutException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.path.PathSelectionFailedException;

public class CircuitBuildTask implements Runnable {
	private final static Logger logger = Logger.getLogger(CircuitBuildTask.class.getName());
	private final CircuitCreationRequest creationRequest;
	private final ConnectionCache connectionCache;
	private final TorInitializationTracker initializationTracker;
	private final CircuitImpl circuit;
	private final CircuitExtender extender;

	private Connection connection = null;
	
	public CircuitBuildTask(CircuitCreationRequest request, ConnectionCache connectionCache, boolean ntorEnabled) {
		this(request, connectionCache, ntorEnabled, null);
	}

	public CircuitBuildTask(CircuitCreationRequest request, ConnectionCache connectionCache, boolean ntorEnabled, TorInitializationTracker initializationTracker) {
		this.creationRequest = request;
		this.connectionCache = connectionCache;
		this.initializationTracker = initializationTracker;
		this.circuit = request.getCircuit();
		this.extender = new CircuitExtender(request.getCircuit(), ntorEnabled);
	}

	public void run() {
		Router firstRouter = null;
		try {
			circuit.notifyCircuitBuildStart();
			creationRequest.choosePath();
			if(logger.isLoggable(Level.FINE)) {
				logger.fine("Opening a new circuit to "+ pathToString(creationRequest));
			}
			firstRouter = creationRequest.getPathElement(0);
			openEntryNodeConnection(firstRouter);
			buildCircuit(firstRouter);
			circuit.notifyCircuitBuildCompleted();
		} catch (ConnectionTimeoutException e) {
			connectionFailed("Timeout connecting to "+ firstRouter);
		} catch (ConnectionFailedException e) {
			connectionFailed("Connection failed to "+ firstRouter + " : " + e.getMessage());
		} catch (ConnectionHandshakeException e) {
			connectionFailed("Handshake error connecting to "+ firstRouter + " : " + e.getMessage());
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			circuitBuildFailed("Circuit building thread interrupted");
		} catch(PathSelectionFailedException e) { 
			circuitBuildFailed(e.getMessage());
		} catch (TorException e) {
			circuitBuildFailed(e.getMessage());
		} catch(Exception e) {
			circuitBuildFailed("Unexpected exception: "+ e);
			logger.log(Level.WARNING, "Unexpected exception while building circuit: "+ e, e);
		}
	}

	private String pathToString(CircuitCreationRequest ccr) {
		final StringBuilder sb = new StringBuilder();
		sb.append("[");
		for(Router r: ccr.getPath()) {
			if(sb.length() > 1)
				sb.append(",");
			sb.append(r.getNickname());
		}
		sb.append("]");
		return sb.toString();
	}

	private void connectionFailed(String message) {
		creationRequest.connectionFailed(message);
		circuit.notifyCircuitBuildFailed();
	}
	
	private void circuitBuildFailed(String message) {
		creationRequest.circuitBuildFailed(message);
		circuit.notifyCircuitBuildFailed();
		if(connection != null) {
			connection.removeCircuit(circuit);
		}
	}
	
	private void openEntryNodeConnection(Router firstRouter) throws ConnectionTimeoutException, ConnectionFailedException, ConnectionHandshakeException, InterruptedException {
		connection = connectionCache.getConnectionTo(firstRouter, creationRequest.isDirectoryCircuit());
		circuit.bindToConnection(connection);
		creationRequest.connectionCompleted(connection);
	}

	private void buildCircuit(Router firstRouter) throws TorException {
		notifyInitialization();
		final CircuitNode firstNode = extender.createFastTo(firstRouter);
		creationRequest.nodeAdded(firstNode);
		
		for(int i = 1; i < creationRequest.getPathLength(); i++) {
			final CircuitNode extendedNode = extender.extendTo(creationRequest.getPathElement(i));
			creationRequest.nodeAdded(extendedNode);
		}
		creationRequest.circuitBuildCompleted(circuit);
		notifyDone();
	}

	private void notifyInitialization() {
		if(initializationTracker != null) {
			final int event = creationRequest.isDirectoryCircuit() ? 
					Tor.BOOTSTRAP_STATUS_ONEHOP_CREATE : Tor.BOOTSTRAP_STATUS_CIRCUIT_CREATE;
			initializationTracker.notifyEvent(event);
		}
	}

	private void notifyDone() {
		if(initializationTracker != null && !creationRequest.isDirectoryCircuit()) {
			initializationTracker.notifyEvent(Tor.BOOTSTRAP_STATUS_DONE);
		}
	}
}
