package com.subgraph.orchid;


public interface Cell {
	/** Command constant for a PADDING type cell. */
	final static int PADDING = 0;

	/** Command constant for a CREATE type cell. */
	final static int CREATE = 1;

	/** Command constant for a CREATED type cell. */
	final static int CREATED = 2;

	/** Command constant for a RELAY type cell. */
	final static int RELAY = 3;

	/** Command constant for a DESTROY type cell. */
	final static int DESTROY = 4;

	/** Command constant for a CREATE_FAST type cell. */
	final static int CREATE_FAST = 5;

	/** Command constant for a CREATED_FAST type cell. */
	final static int CREATED_FAST = 6;

	/** Command constant for a VERSIONS type cell. */
	final static int VERSIONS = 7;

	/** Command constant for a NETINFO type cell. */
	final static int NETINFO = 8;

	/** Command constant for a RELAY_EARLY type cell. */
	final static int RELAY_EARLY = 9;
	
	final static int VPADDING = 128;
	final static int CERTS = 129;
	final static int AUTH_CHALLENGE = 130;
	final static int AUTHENTICATE = 131;
	final static int AUTHORIZE = 132;

	final static int ERROR_NONE = 0;
	final static int ERROR_PROTOCOL = 1;
	final static int ERROR_INTERNAL = 2;
	final static int ERROR_REQUESTED = 3;
	final static int ERROR_HIBERNATING = 4;
	final static int ERROR_RESOURCELIMIT = 5;
	final static int ERROR_CONNECTFAILED = 6;
	final static int ERROR_OR_IDENTITY = 7;
	final static int ERROR_OR_CONN_CLOSED = 8;
	final static int ERROR_FINISHED = 9;
	final static int ERROR_TIMEOUT = 10;
	final static int ERROR_DESTROYED = 11;
	final static int ERROR_NOSUCHSERVICE = 12;

	final static int ADDRESS_TYPE_HOSTNAME = 0x00;
	final static int ADDRESS_TYPE_IPV4     = 0x04;
	final static int ADRESS_TYPE_IPV6      = 0x06;

	/**
	 * The fixed size of a standard cell.
	 */
	final static int CELL_LEN = 512;

	/**
	 * The length of a standard cell header.
	 */
	final static int CELL_HEADER_LEN = 3;

	/**
	 * The header length for a variable length cell (ie: VERSIONS)
	 */
	final static int CELL_VAR_HEADER_LEN = 5;

	/**
	 * The length of the payload space in a standard cell.
	 */
	final static int CELL_PAYLOAD_LEN = CELL_LEN - CELL_HEADER_LEN;

	/**
	 * Return the circuit id field from this cell.
	 * 
	 * @return The circuit id field of this cell.
	 */
	int getCircuitId();

	/**
	 * Return the command field from this cell.
	 *   
	 * @return The command field of this cell.
	 */
	int getCommand();

	/**
	 * Set the internal pointer to the first byte after the cell header.
	 */
	void resetToPayload();

	/**
	 * Return the next byte from the cell and increment the internal pointer by one byte.
	 * 
	 * @return The byte at the current pointer location.
	 */
	int getByte();

	/**
	 * Return the byte at the specified offset into the cell.
	 * 
	 * @param index The cell offset.
	 * @return The byte at the specified offset.
	 */
	int getByteAt(int index);

	/**
	 * Return the next 16-bit big endian value from the cell and increment the internal pointer by two bytes.
	 * 
	 * @return The 16-bit short value at the current pointer location.
	 */
	int getShort();

	/**
	 * Return the 16-bit big endian value at the specified offset into the cell.
	 * 
	 * @param index The cell offset.
	 * @return The 16-bit short value at the specified offset.
	 */
	int getShortAt(int index);

	/**
	 * Return the next 32-bit big endian value from the cell and increment the internal pointer by four bytes.
	 * 
	 * @return The 32-bit integer value at the current pointer location.
	 */
	int getInt();

	/**
	 * Copy <code>buffer.length</code> bytes from the cell into <code>buffer</code>.  The data is copied starting
	 * from the current internal pointer location and afterwards the internal pointer is incremented by <code>buffer.length</code>
	 * bytes.
	 *  
	 * @param buffer The array of bytes to copy the cell data into.
	 */
	void getByteArray(byte[] buffer);

	/**
	 * Return the number of bytes already packed (for outgoing cells) or unpacked (for incoming cells).  This is 
	 * equivalent to the internal pointer position.
	 * 
	 * @return The number of bytes already consumed from this cell.
	 */
	int cellBytesConsumed();

	/**
	 * Return the number of bytes remaining between the current internal pointer and the end of the cell.  If fields
	 * are being added to a new cell for transmission then this value indicates the remaining space in bytes for 
	 * adding new data.  If fields are being read from a received cell then this value describes the number of bytes 
	 * which can be read without overflowing the cell.
	 * 
	 * @return The number of payload bytes remaining in this cell.
	 */
	int cellBytesRemaining();

	/**
	 * Store a byte at the current pointer location and increment the pointer by one byte.
	 * 
	 * @param value The byte value to store.
	 */
	void putByte(int value);

	/**
	 * Store a byte at the specified offset into the cell.
	 * 
	 * @param index The offset in bytes into the cell.
	 * @param value The byte value to store.
	 */
	void putByteAt(int index, int value);

	/**
	 * Store a 16-bit short value in big endian order at the current pointer location and 
	 * increment the pointer by two bytes.
	 * 
	 * @param value The 16-bit short value to store.
	 */
	void putShort(int value);

	/**
	 * Store a 16-bit short value in big endian byte order at the specified offset into the cell 
	 * and increment the pointer by two bytes.
	 * 
	 * @param index The offset in bytes into the cell.
	 * @param value The 16-bit short value to store.
	 */
	void putShortAt(int index, int value);

	/**
	 * Store a 32-bit integer value in big endian order at the current pointer location and
	 * increment the pointer by 4 bytes.
	 * 
	 * @param value The 32-bit integer value to store.
	 */
	void putInt(int value);

	/**
	 * Store the entire array <code>data</code> at the current pointer location and increment
	 * the pointer by <code>data.length</code> bytes.
	 * 
	 * @param data The array of bytes to store in the cell.
	 */
	void putByteArray(byte[] data);

	/**
	 * Store <code>length</code> bytes of the byte array <code>data</code> starting from
	 * <code>offset</code> into the array at the current pointer location and increment 
	 * the pointer by <code>length</code> bytes.
	 * 
	 * @param data The source array of bytes.
	 * @param offset The offset into the source array.
	 * @param length The number of bytes from the source array to store.
	 */
	void putByteArray(byte[] data, int offset, int length);

	/**
	 * Return the entire cell data as a raw array of bytes.  For all cells except
	 * <code>VERSIONS</code>, this array will be exactly <code>CELL_LEN</code> bytes long.
	 * 
	 * @return The cell data as an array of bytes.
	 */
	byte[] getCellBytes();

	void putString(String string);
}
