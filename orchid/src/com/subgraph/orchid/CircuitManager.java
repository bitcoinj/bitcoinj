package com.subgraph.orchid;

import java.util.List;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.data.IPv4Address;


public interface CircuitManager {

	static int DIRECTORY_PURPOSE_CONSENSUS = 1;
	static int DIRECTORY_PURPOSE_CERTIFICATES = 2;
	static int DIRECTORY_PURPOSE_DESCRIPTORS = 3;
	
	/**
	 * Begin automatically building new circuits in the background.
	 */
	void startBuildingCircuits();
	void stopBuildingCircuits(boolean killCircuits);
	/**
	 * Attempt to open an exit stream to the specified destination <code>hostname</code> and
	 * <code>port</code>.
	 * 
	 * @param hostname The name of the host to open an exit connection to.
	 * @param port The port to open an exit connection to.
	 * @return The status response result of attempting to open the exit connection.
	 */
	Stream openExitStreamTo(String hostname, int port) throws InterruptedException, TimeoutException, OpenFailedException;

	/**
	 * Attempt to open an exit stream to the destination specified by <code>address</code> and
	 * <code>port</code>.
	 * 
	 * @param address The address to open an exit connection to.
	 * @param port The port to open an exit connection to.
	 * @return The status response result of attempting the open the exit connection.
	 */
	Stream openExitStreamTo(IPv4Address address, int port) throws InterruptedException, TimeoutException, OpenFailedException;
	
	
	Stream openDirectoryStream(int purpose) throws InterruptedException, TimeoutException, OpenFailedException;
	
	Stream openDirectoryStream() throws InterruptedException, TimeoutException, OpenFailedException;
	
	DirectoryCircuit openDirectoryCircuit() throws OpenFailedException;
	Circuit getCleanInternalCircuit() throws InterruptedException;
	
	ExitCircuit openExitCircuitTo(List<Router> path) throws OpenFailedException;
	InternalCircuit openInternalCircuitTo(List<Router> path) throws OpenFailedException;
	DirectoryCircuit openDirectoryCircuitTo(List<Router> path) throws OpenFailedException;
}
