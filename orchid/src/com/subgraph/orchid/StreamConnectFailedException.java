package com.subgraph.orchid;


public class StreamConnectFailedException extends Exception {

	private static final long serialVersionUID = 8103571310659595097L;
	private final int reason;
	
	public StreamConnectFailedException(int reason) {
		this.reason = reason;
	}
	
	public int getReason() {
		return reason;
	}
	
	public boolean isReasonRetryable() {
		return isRetryableReason(reason);
	}

	/* Copied from edge_reason_is_retriable() since this is not specified */
	private static boolean isRetryableReason(int reasonCode) {
		switch(reasonCode) {
		case RelayCell.REASON_HIBERNATING:
		case RelayCell.REASON_RESOURCELIMIT:
		case RelayCell.REASON_RESOLVEFAILED:
		case RelayCell.REASON_EXITPOLICY:
		case RelayCell.REASON_MISC:
		case RelayCell.REASON_NOROUTE:
			return true;
		default:
			return false;
		}
	}
}
