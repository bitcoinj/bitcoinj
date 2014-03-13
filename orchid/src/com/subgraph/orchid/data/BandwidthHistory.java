package com.subgraph.orchid.data;

import java.util.ArrayList;
import java.util.List;

public class BandwidthHistory {
	
	private final Timestamp reportingTime;
	private final int reportingInterval;
	private final List<Integer>  samples = new ArrayList<Integer>();
	
	public BandwidthHistory(Timestamp reportingTime, int reportingInterval) {
		this.reportingTime = reportingTime;
		this.reportingInterval = reportingInterval;
	}
	
	public int getReportingInterval() {
		return reportingInterval;
	}
	
	public Timestamp getReportingTime() {
		return reportingTime;
	}
	
	public void addSample(int value) {
		samples.add(value);
	}

}
