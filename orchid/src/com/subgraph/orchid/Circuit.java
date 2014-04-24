package com.subgraph.orchid;

import java.util.List;

/**
 * A Circuit represents a logical path through multiple ORs.  Circuits are described in
 * section 5 of tor-spec.txt.
 *
 */
public interface Circuit {
	
	/**
	 * Return <code>true</code> if the circuit is presently in the connected state or
	 * <code>false</code> otherwise.
	 * 
	 * @return Returns <code>true</code> if the circuit is presently connected, or 
	 *                 <code>false</code> otherwise.
	 */
	boolean isConnected();
	
	boolean isPending();
	
	boolean isClean();
	
	boolean isMarkedForClose();
	
	int getSecondsDirty();
	
	/**
	 * Returns the entry router <code>Connection</code> object of this Circuit.  Throws
	 * a TorException if the circuit is not currently open.
	 *  
	 * @return The Connection object for the network connection to the entry router of this 
	 *         circuit.
	 * @throws TorException If this circuit is not currently connected.
	 */
	Connection getConnection();
	
	/**
	 * Returns the curcuit id value for this circuit.
	 * 
	 * @return The circuit id value for this circuit.
	 */
	int getCircuitId();
	
	/**
	 * Create a new relay cell which is configured for delivery to the specified
	 * circuit <code>targetNode</code> with command value <code>relayCommand</code>
	 * and a stream id value of <code>streamId</code>.  The returned <code>RelayCell</code>
	 * can then be used to populate the payload of the cell before delivering it.
	 * 
	 * @param relayCommand The command value to send in the relay cell header.
	 * @param streamId The stream id value to send in the relay cell header.
	 * @param targetNode The target circuit node to encrypt this cell for.
	 * @return A newly created relay cell object.
	 */
	RelayCell createRelayCell(int relayCommand, int streamId, CircuitNode targetNode);
	
	/**
	 * Returns the next relay response cell received on this circuit.  If no response is
	 * received within <code>CIRCUIT_RELAY_RESPONSE_TIMEOUT</code> milliseconds, <code>null</code>
	 * is returned.
	 * 
	 * @return The next relay response cell received on this circuit or <code>null</code> if
	 *         a timeout is reached before the next relay cell arrives.
	 */
	RelayCell receiveRelayCell();
	
	/**
	 * Encrypt and deliver the relay cell <code>cell</code>.
	 * 
	 * @param cell The relay cell to deliver over this circuit.
	 */
	void sendRelayCell(RelayCell cell);
	
	/**
	 * Return the last node or 'hop' in this circuit.
	 * 
	 * @return The final 'hop' or node of this circuit.
	 */
	CircuitNode getFinalCircuitNode();


	void destroyCircuit();

	void deliverRelayCell(Cell cell);

	void deliverControlCell(Cell cell);
	
	List<Stream> getActiveStreams();

	void markForClose();
		
	void appendNode(CircuitNode node);
}
