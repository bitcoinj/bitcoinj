package com.subgraph.orchid.circuits;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.circuits.TorInputStream;

public class TorInputStreamTest {

	private TorInputStream inputStream;
	private Stream mockStream;
	
	@Before
	public void before() {
		mockStream = createMock("mockStream", Stream.class);
		mockStream.close();
		replay(mockStream);
		inputStream = new TorInputStream(mockStream);
	}
	
	@After
	public void after() {
		inputStream.close();
		verify(mockStream);
	}
	
	private static RelayCell createDataCell(byte[] data) {
		final RelayCell cell = createMock("dataCell", RelayCell.class);
		expect(cell.cellBytesRemaining()).andReturn(data.length);
		expectLastCall().times(2);
		expect(cell.getRelayCommand()).andReturn(RelayCell.RELAY_DATA);
		expect(cell.getPayloadBuffer()).andReturn(ByteBuffer.wrap(data));
		replay(cell);
		return cell;
	}
	
	private static RelayCell createEndCell() {
		final RelayCell cell = createMock("endCell", RelayCell.class);
		expect(cell.getRelayCommand()).andReturn(RelayCell.RELAY_END);
		replay(cell);
		return cell;
	}
	
	private void sendData(int... data) {
		byte[] bytes = new byte[data.length];
		for(int i = 0; i < data.length; i++) {
			bytes[i] = (byte) data[i];
		}
		inputStream.addInputCell(createDataCell(bytes));
	}
	
	private void sendEnd() {
		inputStream.addEndCell(createEndCell());
	}
	
	@Test
	public void testAvailable() throws IOException {
		assertEquals(0, inputStream.available());
		sendData(1,2,3);
		assertEquals(3, inputStream.available());
		assertEquals(1, inputStream.read());
		assertEquals(2, inputStream.available());
		sendData(4,5);
		assertEquals(4, inputStream.available());
	}
	
	@Test(timeout=100)
	public void testRead() throws IOException {
		sendData(1,2,3);
		sendData(4);
		sendData(5);
		assertEquals(1, inputStream.read());
		assertEquals(2, inputStream.read());
		sendEnd();
		assertEquals(3, inputStream.read());
		assertEquals(4, inputStream.read());
		assertEquals(5, inputStream.read());
		assertEquals(-1, inputStream.read());
	}
	
	
	private void setupTestClose() throws IOException {
		sendData(1,2,3,4,5,6);
		sendEnd();
		
		assertEquals(1,  inputStream.read());
		assertEquals(2,  inputStream.read());
		
		inputStream.close();
	}
	
	@Test(expected=IOException.class, timeout=100)
	public void testClose1() throws IOException {
		setupTestClose();
		/* throws IOException("Input stream closed") */
		inputStream.read();
	}
	
	@Test(expected=IOException.class, timeout=100)
	public void testClose2() throws IOException {
		setupTestClose();
		/* throws IOException("Input stream closed") */
		inputStream.read(new byte[2]);
	}
	
	@Test(timeout=100)
	public void testReadBuffer() throws IOException {
		final byte[] buffer = new byte[3];
		
		sendData(1,2,3);
		sendData(4,5,6);


		/* read two bytes at offset 1 */
		assertEquals(2, inputStream.read(buffer, 1, 2));
		assertArrayEquals(new byte[] {0, 1, 2}, buffer);
		
		/* read entire buffer (3 bytes) */
		assertEquals(3, inputStream.read(buffer));
		assertArrayEquals(new byte[] {3, 4, 5 }, buffer);
		
		/* reset buffer to {0,0,0}, read entire buffer */
		Arrays.fill(buffer, (byte)0);
		assertEquals(1, inputStream.read(buffer));
		assertArrayEquals(new byte[] { 6, 0, 0 }, buffer);

		sendEnd();
		/* read entire buffer at EOF */
		assertEquals(-1, inputStream.read(buffer));
	}
	
	private boolean doesNullBufferThrowException() throws IOException {
		try {
			inputStream.read(null);
			return false;
		} catch(NullPointerException e) {
			return true;
		}
	}
	
	private boolean throwsOOBException(byte[] b, int off, int len) throws IOException {
		try {
			inputStream.read(b, off, len);
			return false;
		} catch (IndexOutOfBoundsException e) {
			return true;
		}
	}

	private void testOOB(String message, int bufferLength, int off, int len) throws IOException {
		final byte[] buffer = new byte[bufferLength];
		assertTrue(message, throwsOOBException(buffer, off, len));
	}
	
	@Test(timeout=100)
	public void testBadReadArguments() throws IOException {
		final byte[] buffer = new byte[16];
		sendData(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20);
		sendEnd();
		
		assertTrue("Null buffer must throw NPE", doesNullBufferThrowException());
		assertFalse("(offset + len) == b.length must not throw OOB", throwsOOBException(buffer, 8, 8));
		
		testOOB("Negative offset must throw OOB", 16, -2, 4);
		testOOB("Negative length must throw OOB", 16, 0, -10);
		testOOB("off >= b.length must throw OOB", 16, 16, 10);
		testOOB("(off + len) > b.length must throw OOB", 16, 8, 9);
		testOOB("(off + len) < 0 must throw OOB", 16, Integer.MAX_VALUE, 10);
	}
}
