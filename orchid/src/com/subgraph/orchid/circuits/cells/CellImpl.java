package com.subgraph.orchid.circuits.cells;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import com.subgraph.orchid.Cell;

public class CellImpl implements Cell {

	public static CellImpl createCell(int circuitId, int command) {
		return new CellImpl(circuitId, command);
	}

	public static CellImpl createVarCell(int circuitId, int command, int payloadLength) {
		return new CellImpl(circuitId, command, payloadLength);
	}

	public static CellImpl readFromInputStream(InputStream input) throws IOException {
		final ByteBuffer header = readHeaderFromInputStream(input);
		final int circuitId = header.getShort() & 0xFFFF;
		final int command = header.get() & 0xFF;
		
		if(command == VERSIONS || command > 127) {
			return readVarCell(circuitId, command, input);
		}

		final CellImpl cell = new CellImpl(circuitId, command);
		readAll(input, cell.getCellBytes(), CELL_HEADER_LEN, CELL_PAYLOAD_LEN);

		return cell;
	}

	private static ByteBuffer readHeaderFromInputStream(InputStream input) throws IOException {
		final byte[] cellHeader = new byte[CELL_HEADER_LEN];
		readAll(input, cellHeader);
		return ByteBuffer.wrap(cellHeader);
	}

	private static CellImpl readVarCell(int circuitId, int command, InputStream input) throws IOException {
		final byte[] lengthField = new byte[2];
		readAll(input, lengthField);
		final int length = ((lengthField[0] & 0xFF) << 8) | (lengthField[1] & 0xFF);
		CellImpl cell = new CellImpl(circuitId, command, length);
		readAll(input, cell.getCellBytes(), CELL_VAR_HEADER_LEN, length);
		return cell;
	}

	private static void readAll(InputStream input, byte[] buffer) throws IOException {
		readAll(input, buffer, 0, buffer.length);
	}

	private static void readAll(InputStream input, byte[] buffer, int offset, int length) throws IOException {
		int bytesRead = 0;
		while(bytesRead < length) {
			final int n = input.read(buffer, offset + bytesRead, length - bytesRead);
			if(n == -1)
				throw new EOFException();
			bytesRead += n;
		}
	}

	private final int circuitId;
	private final int command;
	protected final ByteBuffer cellBuffer;

	/* Variable length cell constructor (ie: VERSIONS cells only) */
	private CellImpl(int circuitId, int command, int payloadLength) {
		this.circuitId = circuitId;
		this.command = command;
		this.cellBuffer = ByteBuffer.wrap(new byte[CELL_VAR_HEADER_LEN + payloadLength]);
		cellBuffer.putShort((short)circuitId);
		cellBuffer.put((byte)command);
		cellBuffer.putShort((short) payloadLength);
		cellBuffer.mark();
	}

	/* Fixed length cell constructor */
	protected CellImpl(int circuitId, int command) {
		this.circuitId = circuitId;
		this.command = command;
		this.cellBuffer = ByteBuffer.wrap(new byte[CELL_LEN]);
		cellBuffer.putShort((short) circuitId);
		cellBuffer.put((byte) command);
		cellBuffer.mark();
	}

	protected CellImpl(byte[] rawCell) {
		this.cellBuffer = ByteBuffer.wrap(rawCell);
		this.circuitId = cellBuffer.getShort() & 0xFFFF;
		this.command = cellBuffer.get() & 0xFF;
		cellBuffer.mark();
	}
	
	public int getCircuitId() {
		return circuitId;
	}

	public int getCommand() {
		return command;
	}

	public void resetToPayload() {
		cellBuffer.reset();
	}

	public int getByte() {
		return cellBuffer.get() & 0xFF;
	}

	public int getByteAt(int index) {
		return cellBuffer.get(index) & 0xFF;
	}

	public int getShort() {
		return cellBuffer.getShort() & 0xFFFF;
	}

	public int getInt() {
		return cellBuffer.getInt();
	}

	public int getShortAt(int index) {
		return cellBuffer.getShort(index) & 0xFFFF;
	}

	public void getByteArray(byte[] buffer) {
		cellBuffer.get(buffer);
	}

	public int cellBytesConsumed() {
		return cellBuffer.position();
	}

	public int cellBytesRemaining() {
		return cellBuffer.remaining();
	}

	public void putByte(int value) {
		cellBuffer.put((byte) value);
	}

	public void putByteAt(int index, int value) {
		cellBuffer.put(index, (byte) value);
	}

	public void putShort(int value) {
		cellBuffer.putShort((short) value);
	}

	public void putShortAt(int index, int value) {
		cellBuffer.putShort(index, (short) value);
	}

	public void putInt(int value) {
		cellBuffer.putInt(value);
	}

	public void putString(String string) {
		final byte[] bytes = new byte[string.length() + 1];
		for(int i = 0; i < string.length(); i++)
			bytes[i] = (byte) string.charAt(i);
		putByteArray(bytes);
	}

	public void putByteArray(byte[] data) {
		cellBuffer.put(data);
	}

	public void putByteArray(byte[] data, int offset, int length) {
		cellBuffer.put(data, offset, length);
	}

	public byte[] getCellBytes() {
		return cellBuffer.array();
	}

	public String toString() {
		return "Cell: circuit_id="+ circuitId +" command="+ command +" payload_len="+ cellBuffer.position();
	}

	public static String errorToDescription(int errorCode) {
		switch(errorCode) {
		case ERROR_NONE:
			return "No error reason given";
		case ERROR_PROTOCOL:
			return "Tor protocol violation";
		case ERROR_INTERNAL:
			return "Internal error";
		case ERROR_REQUESTED:
			return "Response to a TRUNCATE command sent from client";
		case ERROR_HIBERNATING:
			return "Not currently operating; trying to save bandwidth.";
		case ERROR_RESOURCELIMIT:
			return "Out of memory, sockets, or circuit IDs.";
		case ERROR_CONNECTFAILED:
			return "Unable to reach server.";
		case ERROR_OR_IDENTITY:
			return "Connected to server, but its OR identity was not as expected.";
		case ERROR_OR_CONN_CLOSED:
			return "The OR connection that was carrying this circuit died.";
		case ERROR_FINISHED:
			return "The circuit has expired for being dirty or old.";
		case ERROR_TIMEOUT:
			return "Circuit construction took too long.";
		case ERROR_DESTROYED:
			return "The circuit was destroyed without client TRUNCATE";
		case ERROR_NOSUCHSERVICE:
			return "Request for unknown hidden service";
		default:
			return "Error code "+ errorCode;
		}
	}
}
