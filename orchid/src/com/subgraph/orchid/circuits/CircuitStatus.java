package com.subgraph.orchid.circuits;

import com.subgraph.orchid.crypto.TorRandom;

public class CircuitStatus {

	enum CircuitState {
		UNCONNECTED("Unconnected"),
		BUILDING("Building"),
		FAILED("Failed"),
		OPEN("Open"),
		DESTROYED("Destroyed");
		String name;
		CircuitState(String name) { this.name = name; }
		public String toString() { return name; }
	}

	private long timestampCreated;
	private long timestampDirty;
	private int currentStreamId;
	private Object streamIdLock = new Object();
	private volatile CircuitState state = CircuitState.UNCONNECTED;

	CircuitStatus() {
		initializeCurrentStreamId();
	}

	private void initializeCurrentStreamId() {
		final TorRandom random = new TorRandom();
		currentStreamId = random.nextInt(0xFFFF) + 1;
	}

	synchronized void updateCreatedTimestamp() {
		timestampCreated = System.currentTimeMillis();
		timestampDirty = 0;
	}

	synchronized void updateDirtyTimestamp() {
		if(timestampDirty == 0 && state != CircuitState.BUILDING) {
			timestampDirty = System.currentTimeMillis();
		}
	}

	synchronized long getMillisecondsElapsedSinceCreated() {
		return millisecondsElapsedSince(timestampCreated);
	}

	synchronized long getMillisecondsDirty() {
		return millisecondsElapsedSince(timestampDirty);
	}

	private static long millisecondsElapsedSince(long then) {
		if(then == 0) {
			return 0;
		}
		final long now = System.currentTimeMillis();
		return now - then;
	}

	synchronized boolean isDirty() {
		return timestampDirty != 0;
	}

	void setStateBuilding() {
		state = CircuitState.BUILDING;
	}

	void setStateFailed() {
		state = CircuitState.FAILED;
	}

	void setStateOpen() {
		state = CircuitState.OPEN;
	}

	void setStateDestroyed() {
		state = CircuitState.DESTROYED;
	}

	boolean isBuilding() {
		return state == CircuitState.BUILDING;
	}

	boolean isConnected() {
		return state == CircuitState.OPEN;
	}

	boolean isUnconnected() {
		return state == CircuitState.UNCONNECTED;
	}

	String getStateAsString() {
		if(state == CircuitState.OPEN) {
			return state.toString() + " ["+ getDirtyString() + "]";
		}
		return state.toString();
	}

	private String getDirtyString() {
		if(!isDirty()) {
			return "Clean";
		} else {
			return "Dirty "+ (getMillisecondsDirty() / 1000) +"s"; 
		}
	}
	int nextStreamId() {
		synchronized(streamIdLock) {
			currentStreamId++;
			if(currentStreamId > 0xFFFF)
				currentStreamId = 1;
			return currentStreamId;
		}
	}

}
