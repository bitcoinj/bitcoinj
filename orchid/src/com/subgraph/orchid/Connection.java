package com.subgraph.orchid;


/**
 * A network connection to a Tor onion router.   
 */
public interface Connection {
	/**
	 * Return the {@link Router} associated with this connection.
	 * 
	 * @return The entry router this connection represents.
	 */
	Router getRouter();

	/**
	 * Return <code>true</code> if the socket for this connection has been closed.  Otherwise, <code>false</code>.
	 * 
	 * @return <code>true</code> if this connection is closed or <code>false</code> otherwise.
	 */
	boolean isClosed();
	/**
	 * Send a protocol {@link Cell} on this connection.
	 * 
	 * @param cell The {@link Cell} to transfer.
	 * @throws ConnectionIOException If the cell could not be send because the connection is not connected
	 *                                   or if an error occured while sending the cell data.
	 */
	void sendCell(Cell cell) throws ConnectionIOException;
	
	/**
	 * Remove a Circuit which has been bound to this Connection by a previous call to {@link #bindCircuit(Circuit) bindCircuit}.  
	 * After removing a Circuit, any further received incoming cells for the Circuit will be discarded.
	 * 
	 * @param circuit The Circuit to remove.
	 */
	void removeCircuit(Circuit circuit);
	
	/**
	 * Choose an available circuit id value and bind this Circuit to that id value, returning the id value.  
	 * Once bound, any incoming relay cells will be delivered to the Circuit with {@link Circuit#deliverRelayCell(Cell)}
	 * and other cells will be delivered with {@link Circuit#deliverControlCell(Cell)}.
	 * 
	 * @param circuit The Circuit to bind to this connection.
	 * @return the circuit id value for this binding.
	 */
	int bindCircuit(Circuit circuit);
}
