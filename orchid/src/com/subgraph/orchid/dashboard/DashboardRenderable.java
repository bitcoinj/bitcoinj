package com.subgraph.orchid.dashboard;

import java.io.IOException;
import java.io.PrintWriter;

public interface DashboardRenderable {
	
	static int DASHBOARD_CONNECTIONS           = 1 << 0;
	static int DASHBOARD_CONNECTIONS_VERBOSE   = 1 << 1;
	static int DASHBOARD_PREDICTED_PORTS       = 1 << 2;
	static int DASHBOARD_CIRCUITS              = 1 << 3;
	static int DASHBOARD_STREAMS               = 1 << 4;
	
	void dashboardRender(DashboardRenderer renderer, PrintWriter writer, int flags) throws IOException;
}
