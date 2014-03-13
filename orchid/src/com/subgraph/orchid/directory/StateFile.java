package com.subgraph.orchid.directory;

import java.nio.ByteBuffer;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryStore;
import com.subgraph.orchid.GuardEntry;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.DirectoryStore.CacheFile;
import com.subgraph.orchid.crypto.TorRandom;

public class StateFile {
	private final static Logger logger = Logger.getLogger(StateFile.class.getName());
	
	private final static int DATE_LENGTH = 19;
	
	final static String KEYWORD_ENTRY_GUARD = "EntryGuard";
	final static String KEYWORD_ENTRY_GUARD_ADDED_BY = "EntryGuardAddedBy";
	final static String KEYWORD_ENTRY_GUARD_DOWN_SINCE = "EntryGuardDownSince";
	final static String KEYWORD_ENTRY_GUARD_UNLISTED_SINCE = "EntryGuardUnlistedSince";
	
	private final List<GuardEntryImpl> guardEntries = new ArrayList<GuardEntryImpl>();
	private final TorRandom random = new TorRandom();
	private final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	
	private class Line {
		final String line;
		int offset;
		
		Line(String line) {
			this.line = line;
			offset = 0;
		}
		
		private boolean hasChars() {
			return offset < line.length();
		}
		
		private char getChar() {
			return line.charAt(offset);
		}

		private void incrementOffset(int n) {
			offset += n;
			if(offset > line.length()) {
				offset = line.length();
			}
		}
	
		private void skipWhitespace() {
			while(hasChars() && Character.isWhitespace(getChar())) {
				offset += 1;
			}
		}
		
		String nextToken() {
			skipWhitespace();
			if(!hasChars()) {
				return null;
			}
		
			final StringBuilder token = new StringBuilder();
			while(hasChars() && !Character.isWhitespace(getChar())) {
				token.append(getChar());
				offset += 1;
			}
			return token.toString();
		}
		
		Date parseDate() {
			skipWhitespace();
			if(!hasChars()) {
				return null;
			}
			try {
				final Date date = dateFormat.parse(line.substring(offset));
				incrementOffset(DATE_LENGTH);
				return date;
			} catch (ParseException e) {
				return null;
			}
		}
	}

	String formatDate(Date date) {
		return dateFormat.format(date);
	}

	private final DirectoryStore directoryStore;
	private final Directory directory;
	
	StateFile(DirectoryStore store, Directory directory) {
		this.directoryStore = store;
		this.directory = directory;
	}

	public GuardEntry createGuardEntryFor(Router router) {
		final GuardEntryImpl entry = new GuardEntryImpl(directory, this, router.getNickname(), router.getIdentityHash().toString());
		final String version = Tor.getImplementation() + "-" + Tor.getVersion();
		entry.setVersion(version);
		
		/* 
		 * "Choose expiry time smudged over the last month."
		 * 
		 * See add_an_entry_guard() in entrynodes.c 
		 */
		final long createTime = (new Date()).getTime() - (random.nextInt(3600 * 24 * 30) * 1000L);
		entry.setCreatedTime(new Date(createTime));
		return entry;
	}

	public List<GuardEntry> getGuardEntries() {
		synchronized (guardEntries) {
			return new ArrayList<GuardEntry>(guardEntries);
		}
	}

	public void removeGuardEntry(GuardEntry entry) {
		synchronized (guardEntries) {
			guardEntries.remove(entry);
			writeFile();
		}
	}

	public void addGuardEntry(GuardEntry entry) {
		addGuardEntry(entry, true);
	}

	private void addGuardEntry(GuardEntry entry, boolean writeFile) {
		synchronized(guardEntries) {
			if(guardEntries.contains(entry)) {
				return;
			}
			final GuardEntryImpl impl = (GuardEntryImpl) entry;
			guardEntries.add(impl);
			synchronized (impl) {
				impl.setAddedFlag();
				if(writeFile) {
					writeFile();
				}
			}
		}
	}

	void writeFile() {
		directoryStore.writeData(CacheFile.STATE, getFileContents());
	}
	
	ByteBuffer getFileContents() {
		final StringBuilder sb = new StringBuilder();
		synchronized (guardEntries) {
			for(GuardEntryImpl entry: guardEntries) {
				sb.append(entry.writeToString());
			}
		}
		return ByteBuffer.wrap(sb.toString().getBytes(Tor.getDefaultCharset()));
	}

	void parseBuffer(ByteBuffer buffer) {
		synchronized (guardEntries) {
			guardEntries.clear();
			loadGuardEntries(buffer);
		}
	}

	private void loadGuardEntries(ByteBuffer buffer) {
		GuardEntryImpl currentEntry = null;
		while(true) {
			Line line = readLine(buffer);
			if(line == null) {
				addEntryIfValid(currentEntry);
				return;
			}
			currentEntry = processLine(line, currentEntry);
		}
	}

	private GuardEntryImpl processLine(Line line, GuardEntryImpl current) {
		final String keyword = line.nextToken();
		if(keyword == null) {
			return current;
		} else if(keyword.equals(KEYWORD_ENTRY_GUARD)) {
			addEntryIfValid(current);
			GuardEntryImpl newEntry = processEntryGuardLine(line);
			if(newEntry == null) {
				return current;
			} else {
				return newEntry;
			}
		} else if(keyword.equals(KEYWORD_ENTRY_GUARD_ADDED_BY)) {
			processEntryGuardAddedBy(line, current);
			return current;
		} else if(keyword.equals(KEYWORD_ENTRY_GUARD_DOWN_SINCE)) {
			processEntryGuardDownSince(line, current);
			return current;
		} else if(keyword.equals(KEYWORD_ENTRY_GUARD_UNLISTED_SINCE)) {
			processEntryGuardUnlistedSince(line, current);
			return current;
		} else {
			return current;
		}
	}
	
	private GuardEntryImpl processEntryGuardLine(Line line) {
		final String name = line.nextToken();
		final String identity = line.nextToken();
		if(name == null || name.isEmpty() || identity == null || identity.isEmpty()) {
			logger.warning("Failed to parse EntryGuard line: "+ line.line);
			return null;
		}
		return new GuardEntryImpl(directory, this, name, identity);
	}
	
	private void processEntryGuardAddedBy(Line line, GuardEntryImpl current) {
		if(current == null) {
			logger.warning("EntryGuardAddedBy line seen before EntryGuard in state file");
			return;
		}
		final String identity = line.nextToken();
		final String version = line.nextToken();
		final Date created = line.parseDate();
		if(identity == null || identity.isEmpty() || version == null || version.isEmpty() || created == null) {
			logger.warning("Missing EntryGuardAddedBy field in state file");
			return;
		}
		current.setVersion(version);
		current.setCreatedTime(created);
	}
	
	private void processEntryGuardDownSince(Line line, GuardEntryImpl current) {
		if(current == null) {
			logger.warning("EntryGuardDownSince line seen before EntryGuard in state file");
			return;
		}
		
		final Date downSince = line.parseDate();
		final Date lastTried = line.parseDate();
		if(downSince == null) {
			logger.warning("Failed to parse date field in EntryGuardDownSince line in state file");
			return;
		}
		current.setDownSince(downSince, lastTried);
	}
	
	private void processEntryGuardUnlistedSince(Line line, GuardEntryImpl current) {
		if(current == null) {
			logger.warning("EntryGuardUnlistedSince line seen before EntryGuard in state file");
			return;
		}
		final Date unlistedSince = line.parseDate();
		if(unlistedSince == null) {
			logger.warning("Failed to parse date field in EntryGuardUnlistedSince line in state file");
			return;
		}
		current.setUnlistedSince(unlistedSince);
	}

	private void addEntryIfValid(GuardEntryImpl entry) {
		if(isValidEntry(entry)) {
			addGuardEntry(entry, false);
		}
	}

	private boolean isValidEntry(GuardEntryImpl entry) {
		return entry != null &&
				entry.getNickname() != null && 
				entry.getIdentity() != null && 
				entry.getVersion() != null && 
				entry.getCreatedTime() != null;
	}

	private Line readLine(ByteBuffer buffer) {
		if(!buffer.hasRemaining()) {
			return null;
		}
		
		final StringBuilder sb = new StringBuilder();
		while(buffer.hasRemaining()) {
			char c = (char) (buffer.get() & 0xFF);
			if(c == '\n') {
				return new Line(sb.toString());
			} else if(c != '\r') {
				sb.append(c);
			}
		}
		return new Line(sb.toString());
	}
}
