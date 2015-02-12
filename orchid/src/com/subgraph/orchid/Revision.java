package com.subgraph.orchid;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Revision {
	private final static String REVISION_FILE_PATH = "/build-revision";
	
	public static String getBuildRevision() {
		final InputStream input = tryResourceOpen();
		if(input == null) {
			return "";
		}
		try {
			return readFirstLine(input);
		} catch (IOException e) {
			return "";
		}
	}
	
	private static InputStream tryResourceOpen() {
		return Revision.class.getResourceAsStream(REVISION_FILE_PATH);
	}

	private static String readFirstLine(InputStream input) throws IOException {
		try {
			final BufferedReader reader = new BufferedReader(new InputStreamReader(input));
			return reader.readLine();
		} finally {
			input.close();
		}
	}
}
