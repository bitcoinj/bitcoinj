package com.subgraph.orchid;

/**
 * This callback interface is used for reporting progress when
 * opening a new circuit.  An instance of this interface is passed
 * to the {@link Circuit#openCircuit(java.util.List, CircuitBuildHandler)} 
 * method.
 * 
 * The normal sequence of callbacks which are fired when a circuit is opened
 * successfully is {@link #connectionCompleted(Connection)} for the initial 
 * connection to the entry router, followed by one or more 
 * {@link #nodeAdded(CircuitNode)} as the circuit is extended with new nodes.
 * When all requested nodes in the path have been added successfully to the
 * circuit {@link #circuitBuildCompleted(Circuit)} is called and passed the
 * newly constructed circuit.
 * 
 * @see Circuit#openCircuit()
 * 
 */
public interface CircuitBuildHandler {
	/**
	 * Called when a network connection to the entry node has completed 
	 * successfully or if a network connection to the specified entry router
	 * already exists.
	 * 
	 * @param connection The completed connection instance.
	 */
	void connectionCompleted(Connection connection);

	/**
	 * The circuit build has failed because the network connection to the
	 * entry node failed.  No further callback methods will be called after
	 * this failure has been reported.
	 * 
	 * @param reason A description of the reason for failing to connect to
	 *               the entry node.
	 */
	void connectionFailed(String reason);

	/**
	 * A node or 'hop' has been added to the circuit which is being created.
	 * 
	 * @param node The newly added circuit node.
	 */
	void nodeAdded(CircuitNode node);

	/**
	 * The circuit has been successfully built and is ready for use.
	 * 
	 * @param circuit The newly constructed circuit.
	 */
	void circuitBuildCompleted(Circuit circuit);

	/**
	 * Called if the circuit build fails after connecting to the entry node.
	 * 
	 * @param reason A description of the reason the circuit build has failed.
	 */
	void circuitBuildFailed(String reason);
}
