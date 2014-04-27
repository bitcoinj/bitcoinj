package com.subgraph.orchid;



/**
 * Represents the state of a single onion router hop in a connected or connecting {@link Circuit}
 */
public interface CircuitNode {
	/**
	 * Return the {@link Router} associated with this node.
	 *
	 * @return The {@link Router} for this hop of the circuit chain.
	 */
	Router getRouter();

	/**
	 * Update the 'forward' cryptographic digest state for this
	 * node with the contents of <code>cell</code>
	 * 
	 * @param cell The {@link RelayCell} to add to the digest.
	 */
	void updateForwardDigest(RelayCell cell);

	/**
	 * Return the current 'forward' running digest value for this 
	 * node as an array of <code>TOR_DIGEST_SIZE</code> bytes.
	 * 
	 * @return The current 'forward' running digest value for this node.
	 */
	byte[] getForwardDigestBytes();

	/**
	 * Encrypt a {@link RelayCell} for this node with the current
	 * 'forward' cipher state.
	 * 
	 * @param cell The {@link RelayCell} to encrypt.
	 */
	void encryptForwardCell(RelayCell cell);

	/**
	 * Return the {@link CircuitNode} which immediately preceeds this
	 * one in the circuit node chain or <code>null</code> if this is
	 * the first hop.
	 * 
	 * @return The previous {@link CircuitNode} in the chain or <code>
	 *         null</code> if this is the first node.
	 */
	CircuitNode getPreviousNode();

	/**
	 * Return immediately if the packaging window for this node is open (ie: greater than 0), otherwise
	 * block until the circuit is destroyed or the window is incremented by receiving a RELAY_SENDME cell
	 * from this node.
	 */
	void waitForSendWindow();

	/**
	 * If the packaging window for this node is open (ie: greater than 0) this method
	 * decrements the packaging window by 1 and returns immediately, otherwise it will
	 * block until the circuit is destroyed or the window is incremented by receiving 
	 * a RELAY_SENDME cell from this node.  This method will always decrement the packaging
	 * window before returning unless the circuit has been destroyed. 
	 */
	void waitForSendWindowAndDecrement();

	/**
	 * This method is called to signal that a RELAY_SENDME cell has been received from this
	 * node and the packaging window should be incremented.  This will also wake up any threads
	 * that are waiting for the packaging window to open.
	 */
	void incrementSendWindow();

	/**
	 * This method is called when a RELAY_DATA cell is received from this node to decrement
	 * the deliver window counter.
	 */
	void decrementDeliverWindow();

	/**
	 * Examines the delivery window and determines if it would be an appropriate time to
	 * send a RELAY_SENDME cell.  If this method returns true, it increments the delivery
	 * window assuming that a RELAY_SENDME cell will be transmitted.
	 * 
	 * @return Returns true if the deliver window is small enough that sending a RELAY_SENDME
	 * cell would be appropriate.
	 */
	boolean considerSendingSendme();
	
	boolean decryptBackwardCell(Cell cell);
}
