package com.subgraph.orchid.circuits;
 
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.exitpolicy.ExitTarget;
import com.subgraph.orchid.misc.GuardedBy;

public class StreamExitRequest implements ExitTarget {
	
	private enum CompletionStatus {NOT_COMPLETED, SUCCESS, TIMEOUT, STREAM_OPEN_FAILURE, EXIT_FAILURE, INTERRUPTED};
	
	private final boolean isAddress;
	private final IPv4Address address;
	private final String hostname;
	private final int port;
	private final Object requestCompletionLock;
	
	@GuardedBy("requestCompletionLock") private CompletionStatus completionStatus;	
	@GuardedBy("requestCompletionLock") private Stream stream;
	@GuardedBy("requestCompletionLock") private int streamOpenFailReason;
	
	@GuardedBy("this") private boolean isReserved;
	@GuardedBy("this") private int retryCount;
	@GuardedBy("this") private long specificTimeout;

	StreamExitRequest(Object requestCompletionLock, IPv4Address address, int port) {
		this(requestCompletionLock, true, "", address, port);
	}

	StreamExitRequest(Object requestCompletionLock, String hostname, int port) {
		this(requestCompletionLock, false, hostname, null, port);
	}
	
	private StreamExitRequest(Object requestCompletionLock, boolean isAddress, String hostname, IPv4Address address, int port) {
		this.requestCompletionLock = requestCompletionLock;
		this.isAddress = isAddress;
		this.hostname = hostname;
		this.address = address;
		this.port = port;
		this.completionStatus = CompletionStatus.NOT_COMPLETED;
	}

	public boolean isAddressTarget() {
		return isAddress;
	}

	public IPv4Address getAddress() {
		return address;
	}

	public String getHostname() {
		return hostname;
	}

	public int getPort() {
		return port;
	}

	public synchronized void setStreamTimeout(long timeout) {
		specificTimeout = timeout;
	}
	
	public synchronized long getStreamTimeout() {
		if(specificTimeout > 0) {
			return specificTimeout;
		} else if(retryCount < 2) {
			return 10 * 1000;
		} else {
			return 15 * 1000;
		}
	}

	void setCompletedTimeout() {
		synchronized (requestCompletionLock) {
			newStatus(CompletionStatus.TIMEOUT);
		}
	}
	
	void setExitFailed() {
		synchronized (requestCompletionLock) {
			newStatus(CompletionStatus.EXIT_FAILURE);
		}
	}
	
	void setStreamOpenFailure(int reason) {
		synchronized (requestCompletionLock) {
			streamOpenFailReason = reason;
			newStatus(CompletionStatus.STREAM_OPEN_FAILURE);
		}
	}
	
	void setCompletedSuccessfully(Stream stream) {
		synchronized (requestCompletionLock) {
			this.stream = stream;
			newStatus(CompletionStatus.SUCCESS);
		}
	}
	
	void setInterrupted() {
		synchronized (requestCompletionLock) {
			newStatus(CompletionStatus.INTERRUPTED);	
		}
	}

	private void newStatus(CompletionStatus newStatus) {
		if(completionStatus != CompletionStatus.NOT_COMPLETED) {
			throw new IllegalStateException("Attempt to set completion state to " + newStatus +" while status is "+ completionStatus);
		}
		completionStatus = newStatus;
		requestCompletionLock.notifyAll();
	}

	
	Stream getStream() throws OpenFailedException, TimeoutException, StreamConnectFailedException, InterruptedException {
		synchronized(requestCompletionLock) {
			switch(completionStatus) {
			case NOT_COMPLETED:
				throw new IllegalStateException("Request not completed");
			case EXIT_FAILURE:
				throw new OpenFailedException("Failure at exit node");
			case TIMEOUT:
				throw new TimeoutException();
			case STREAM_OPEN_FAILURE:
				throw new StreamConnectFailedException(streamOpenFailReason);
			case INTERRUPTED:
				throw new InterruptedException();
			case SUCCESS:
				return stream;
			default:
				throw new IllegalStateException("Unknown completion status");
			}
		}
	}

	synchronized void resetForRetry() {
		synchronized (requestCompletionLock) {
			streamOpenFailReason = 0;
			completionStatus = CompletionStatus.NOT_COMPLETED;
		}
		retryCount += 1;
		isReserved = false;
	}

	boolean isCompleted() {
		synchronized (requestCompletionLock) {
			return completionStatus != CompletionStatus.NOT_COMPLETED;
		}
	}
	
	synchronized boolean reserveRequest() {
		if(isReserved) return false;
		isReserved = true;
		return true;
	}
	
	synchronized boolean isReserved() {
		return isReserved;
	}
	
	public String toString() {
		if(isAddress)
			return address + ":"+ port;
		else
			return hostname + ":"+ port;
	}
}
