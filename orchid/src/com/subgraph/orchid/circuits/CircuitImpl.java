package com.subgraph.orchid.circuits;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.DirectoryCircuit;
import com.subgraph.orchid.ExitCircuit;
import com.subgraph.orchid.InternalCircuit;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.path.CircuitPathChooser;
import com.subgraph.orchid.circuits.path.PathSelectionFailedException;
import com.subgraph.orchid.dashboard.DashboardRenderable;
import com.subgraph.orchid.dashboard.DashboardRenderer;

/**
 * This class represents an established circuit through the Tor network.
 *
 */
public abstract class CircuitImpl implements Circuit, DashboardRenderable {
	protected final static Logger logger = Logger.getLogger(CircuitImpl.class.getName());
	
	static ExitCircuit createExitCircuit(CircuitManagerImpl circuitManager, Router exitRouter) {
		return new ExitCircuitImpl(circuitManager, exitRouter);
	}
	
	static ExitCircuit createExitCircuitTo(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
		return new ExitCircuitImpl(circuitManager, prechosenPath);
	}
	
	static DirectoryCircuit createDirectoryCircuit(CircuitManagerImpl circuitManager) {
		return new DirectoryCircuitImpl(circuitManager, null);
	}
	
	static DirectoryCircuit createDirectoryCircuitTo(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
		return new DirectoryCircuitImpl(circuitManager, prechosenPath);
	}
	
	static InternalCircuit createInternalCircuitTo(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
		return new InternalCircuitImpl(circuitManager, prechosenPath);
	}

	private final CircuitManagerImpl circuitManager;
	protected final List<Router> prechosenPath;
	
	private final List<CircuitNode> nodeList;
	private final CircuitStatus status;

	private CircuitIO io;


	
		
	
	
	protected CircuitImpl(CircuitManagerImpl circuitManager) {
		this(circuitManager, null);
	}
	
	protected CircuitImpl(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
		nodeList = new ArrayList<CircuitNode>();
		this.circuitManager = circuitManager;
		this.prechosenPath = prechosenPath;
		status = new CircuitStatus();
	}

	List<Router> choosePath(CircuitPathChooser pathChooser) throws InterruptedException, PathSelectionFailedException {
		if(prechosenPath != null) {
			return new ArrayList<Router>(prechosenPath);
		} else {
			return choosePathForCircuit(pathChooser);
		}
	}

	protected abstract List<Router> choosePathForCircuit(CircuitPathChooser pathChooser) throws InterruptedException, PathSelectionFailedException;

	void bindToConnection(Connection connection) {
		if(io != null) {
			throw new IllegalStateException("Circuit already bound to a connection");
		}
		final int id = connection.bindCircuit(this);
		io = new CircuitIO(this, connection, id);
	}

	public void markForClose() {
		if(io != null) {
			io.markForClose();
		}
	}

	public boolean isMarkedForClose() {
		if(io == null) {
			return false;
		} else {
			return io.isMarkedForClose();
		}
	}
	
	CircuitStatus getStatus() {
		return status;
	}
	
	public boolean isConnected() {
		return status.isConnected();
	}

	public boolean isPending() {
		return status.isBuilding();
	}
	
	public boolean isClean() {
		return !status.isDirty();
	}
	
	public int getSecondsDirty() {
		return (int) (status.getMillisecondsDirty() / 1000);
	}

	void notifyCircuitBuildStart() {
		if(!status.isUnconnected()) {
			throw new IllegalStateException("Can only connect UNCONNECTED circuits");
		}
		status.updateCreatedTimestamp();
		status.setStateBuilding();
		circuitManager.addActiveCircuit(this);
	}
	
	void notifyCircuitBuildFailed() {
		status.setStateFailed();
		circuitManager.removeActiveCircuit(this);
	}
	
	void notifyCircuitBuildCompleted() {
		status.setStateOpen();
		status.updateCreatedTimestamp();
	}
	
	public Connection getConnection() {
		if(!isConnected())
			throw new TorException("Circuit is not connected.");
		return io.getConnection();
	}

	public int getCircuitId() {
		if(io == null) {
			return 0;
		} else {
			return io.getCircuitId();
		}
	}

	public void sendRelayCell(RelayCell cell) {
		io.sendRelayCellTo(cell, cell.getCircuitNode());
	}

	public void sendRelayCellToFinalNode(RelayCell cell) {
		io.sendRelayCellTo(cell, getFinalCircuitNode());
	}

	public void appendNode(CircuitNode node) {
		nodeList.add(node);
	}

	List<CircuitNode> getNodeList() {
		return nodeList;
	}

	int getCircuitLength() {
		return nodeList.size();
	}

	public CircuitNode getFinalCircuitNode() {
		if(nodeList.isEmpty())
			throw new TorException("getFinalCircuitNode() called on empty circuit");
		return nodeList.get( getCircuitLength() - 1);
	}

	public RelayCell createRelayCell(int relayCommand, int streamId, CircuitNode targetNode) {
		return io.createRelayCell(relayCommand, streamId, targetNode);
	}

	public RelayCell receiveRelayCell() {
		return io.dequeueRelayResponseCell();
	}

	void sendCell(Cell cell) {
		io.sendCell(cell);
	}
	
	Cell receiveControlCellResponse() {
		return io.receiveControlCellResponse();
	}

	/*
	 * This is called by the cell reading thread in ConnectionImpl to deliver control cells 
	 * associated with this circuit (CREATED or CREATED_FAST).
	 */
	public void deliverControlCell(Cell cell) {
		io.deliverControlCell(cell);
	}

	/* This is called by the cell reading thread in ConnectionImpl to deliver RELAY cells. */
	public void deliverRelayCell(Cell cell) {
		io.deliverRelayCell(cell);
	}

	protected StreamImpl createNewStream(boolean autoclose) {
		return io.createNewStream(autoclose);
	}
	protected StreamImpl createNewStream() {
		return createNewStream(false);
	}

	void setStateDestroyed() {
		status.setStateDestroyed();
		circuitManager.removeActiveCircuit(this);
	}

	public void destroyCircuit() {
		// We might not have bound this circuit yet
		if (io != null) {
			io.destroyCircuit();
		}
		circuitManager.removeActiveCircuit(this);
	}


	public void removeStream(StreamImpl stream) {
		io.removeStream(stream);
	}

	protected Stream processStreamOpenException(Exception e) throws InterruptedException, TimeoutException, StreamConnectFailedException {
		if(e instanceof InterruptedException) {
			throw (InterruptedException) e;
		} else if(e instanceof TimeoutException) {
			throw(TimeoutException) e;
		} else if(e instanceof StreamConnectFailedException) {
			throw(StreamConnectFailedException) e;
		} else {
			throw new IllegalStateException();
		}
	}
	
	protected abstract String getCircuitTypeLabel();
	
	public String toString() {
		return "  Circuit ("+ getCircuitTypeLabel() + ") id="+ getCircuitId() +" state=" + status.getStateAsString() +" "+ pathToString();
	}

	
	protected String pathToString() {
		final StringBuilder sb = new StringBuilder();
		sb.append("[");
		for(CircuitNode node: nodeList) {
			if(sb.length() > 1)
				sb.append(",");
			sb.append(node.toString());
		}
		sb.append("]");
		return sb.toString();
	}

	public List<Stream> getActiveStreams() {
		if(io == null) {
			return Collections.emptyList();
		} else {
			return io.getActiveStreams();
		}
	}

	public void dashboardRender(DashboardRenderer renderer, PrintWriter writer, int flags) throws IOException {
		if(io != null) {
			writer.println(toString());
			renderer.renderComponent(writer, flags, io);
		}
	}	
}
