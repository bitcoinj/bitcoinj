package com.subgraph.orchid.dashboard;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.Socket;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class DashboardConnection implements Runnable {
	
	private final static int REFRESH_INTERVAL = 1000;

	private final Dashboard dashboard;
	private final Socket socket;
	private final ScheduledExecutorService refreshExecutor;
	
	public DashboardConnection(Dashboard dashboard, Socket socket) {
		this.dashboard = dashboard;
		this.socket = socket;
		this.refreshExecutor = new ScheduledThreadPoolExecutor(1);
	}

	public void run() {
		ScheduledFuture<?> handle = null;
		try {
			final PrintWriter writer = new PrintWriter(socket.getOutputStream());
			handle = refreshExecutor.scheduleAtFixedRate(createRefreshRunnable(writer), 0, REFRESH_INTERVAL, TimeUnit.MILLISECONDS);
			runInputLoop(socket.getInputStream());
		} catch (IOException e) {
			closeQuietly(socket);
		} finally {
			if(handle != null) {
				handle.cancel(true);
			}
			refreshExecutor.shutdown();
		}
	}

	private void closeQuietly(Socket s) {
		try {
			s.close();
		} catch (IOException e) { }
	}

	private void runInputLoop(InputStream input) throws IOException {
		int c;
		
		while((c = input.read()) != -1) {
			switch(c) {
			case 'c':
				toggleFlagWithVerbose(DashboardRenderable.DASHBOARD_CONNECTIONS, DashboardRenderable.DASHBOARD_CONNECTIONS_VERBOSE);
				break;
			case 'p':
				toggleFlag(DashboardRenderable.DASHBOARD_PREDICTED_PORTS);
				break;
			default:
				break;
			}
		}
	}

	// Rotate between 3 states
	//    0 (no flags),
	//    basicFlag,
	//    basicFlag|verboseFlag
	private void toggleFlagWithVerbose(int basicFlag, int verboseFlag) {
		if(dashboard.isEnabled(verboseFlag)) {
			dashboard.disableFlag(basicFlag | verboseFlag);
		} else if(dashboard.isEnabled(basicFlag)) {
			dashboard.enableFlag(verboseFlag);
		} else {
			dashboard.enableFlag(basicFlag);
		}
	}
	
	private void toggleFlag(int flag) {
		if(dashboard.isEnabled(flag)) {
			dashboard.disableFlag(flag);
		} else {
			dashboard.enableFlag(flag);
		}
	}

	private void hideCursor(Writer writer) throws IOException {
		emitCSI(writer);
		writer.write("?25l");
	}

	private void emitCSI(Writer writer) throws IOException {
		writer.append((char) 0x1B);
		writer.append('[');
	}
	
	private void clear(PrintWriter writer) throws IOException {
		emitCSI(writer);
		writer.write("2J");
	}
	
	private void moveTo(PrintWriter writer, int x, int y) throws IOException {
		emitCSI(writer);
		writer.printf("%d;%dH", x+1, y+1);
	}
	
	private void refresh(PrintWriter writer) {
		try {
			if(socket.isClosed()) {
				return;
			}
			hideCursor(writer);
			clear(writer);
			moveTo(writer, 0, 0);
			dashboard.renderAll(writer);
			writer.flush();
		} catch(IOException e) {
			closeQuietly(socket);
		}
	}

	private Runnable createRefreshRunnable(final PrintWriter writer) {
		return new Runnable() {
			public void run() {
				refresh(writer);
			}
		};
	}
}
