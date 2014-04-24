package com.subgraph.orchid.directory;

import java.util.Date;

import com.subgraph.orchid.Directory;
import com.subgraph.orchid.GuardEntry;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.data.HexDigest;

public class GuardEntryImpl implements GuardEntry {
	private final static String NL = System.getProperty("line.separator");
	
	private final Directory directory;
	private final StateFile stateFile;
	private final String nickname;
	private final String identity;
	private final Object lock = new Object();
	private String version;
	private Date createdTime;
	
	private boolean isAdded;
	private Date unlistedSince;
	private Date downSince;
	private Date lastConnect;
	
	GuardEntryImpl(Directory directory, StateFile stateFile, String nickname, String identity) {
		this.directory = directory;
		this.stateFile = stateFile;
		this.nickname = nickname;
		this.identity = identity;
	}

	void setAddedFlag() {
		isAdded = true;
	}
	
	void setVersion(String version) {
		this.version = version;
	}
	
	void setCreatedTime(Date date) {
		this.createdTime = date;
	}

	void setUnlistedSince(Date date) {
		synchronized(lock) {
			unlistedSince = date;
		}
	}
	
	void setDownSince(Date downSince, Date lastTried) {
		synchronized (lock) {
			this.downSince = downSince;
			this.lastConnect = lastTried;
		}
	}

	public boolean isAdded() {
		return isAdded;
	}

	public void markAsDown() {
		synchronized(lock) {
			final Date now = new Date();
			if(downSince == null) {
				downSince = now;
			} else {
				lastConnect = now;
			}
		}
		if(isAdded) {
			stateFile.writeFile();
		}
	}
	
	public void clearDownSince() {
		synchronized (lock) {
			downSince = null;
			lastConnect = null;
		}
		if(isAdded) {
			stateFile.writeFile();
		}
	}

	public void clearUnlistedSince() {
		synchronized (lock) {
			unlistedSince = null;
		}
		if(isAdded) {
			stateFile.writeFile();
		}
	}

	public String getNickname() {
		return nickname;
	}

	public String getIdentity() {
		return identity;
	}

	public String getVersion() {
		return version;
	}

	public Date getCreatedTime() {
		synchronized (lock) {
			return dup(createdTime);
		}
	}

	public Date getDownSince() {
		synchronized (lock) {
			return dup(downSince);	
		}
	}

	public Date getLastConnectAttempt() {
		synchronized (lock) {
			return dup(lastConnect);
		}
	}

	public Date getUnlistedSince() {
		synchronized (lock) {
			return dup(unlistedSince);
		}
	}
	
	private Date dup(Date date) {
		if(date == null) {
			return null;
		} else {
			return new Date(date.getTime());
		}
	}

	public String writeToString() {
		final StringBuilder sb = new StringBuilder();
		synchronized (lock) {
			appendEntryGuardLine(sb);
			appendEntryGuardAddedBy(sb);
			if(downSince != null) {
				appendEntryGuardDownSince(sb);
			}
			if(unlistedSince != null) {
				appendEntryGuardUnlistedSince(sb);
			}
		}
		return sb.toString();
	}
	
	private void appendEntryGuardLine(StringBuilder sb) {
		sb.append(StateFile.KEYWORD_ENTRY_GUARD);
		sb.append(" ");
		sb.append(nickname);
		sb.append(" ");
		sb.append(identity);
		sb.append(NL);
	}
	
	
	private void appendEntryGuardAddedBy(StringBuilder sb) {
		sb.append(StateFile.KEYWORD_ENTRY_GUARD_ADDED_BY);
		sb.append(" ");
		sb.append(identity);
		sb.append(" ");
		sb.append(version);
		sb.append(" ");
		sb.append(formatDate(createdTime));
		sb.append(NL);
	}
	
	private void appendEntryGuardDownSince(StringBuilder sb) {
		if(downSince == null) {
			return;
		}
		sb.append(StateFile.KEYWORD_ENTRY_GUARD_DOWN_SINCE);
		sb.append(" ");
		sb.append(formatDate(downSince));
		if(lastConnect != null) {
			sb.append(" ");
			sb.append(formatDate(lastConnect));
		}
		sb.append(NL);
	}
	
	private void appendEntryGuardUnlistedSince(StringBuilder sb) {
		if(unlistedSince == null) {
			return;
		}
		sb.append(StateFile.KEYWORD_ENTRY_GUARD_UNLISTED_SINCE);
		sb.append(" ");
		sb.append(formatDate(unlistedSince));
		sb.append(NL);
	}

	private String formatDate(Date date) {
		return stateFile.formatDate(date);
	}

	public Router getRouterForEntry() {
		final HexDigest id = HexDigest.createFromString(identity);
		return directory.getRouterByIdentity(id);
	}

	public boolean testCurrentlyUsable() {
		final Router router = getRouterForEntry();
		boolean isUsable = router != null && router.isValid() && router.isPossibleGuard() && router.isRunning();
		if(isUsable) {
			markUsable();
			return true;
		} else {
			markUnusable();
			return false;
		}
	}
	
	private void markUsable() {
		synchronized (lock) {
			if(unlistedSince != null) {
				unlistedSince = null;
				if(isAdded) {
					stateFile.writeFile();
				}
			}
		}
	}
	
	private synchronized void markUnusable() {
		synchronized (lock) {
			if(unlistedSince == null) {
				unlistedSince = new Date();
				if(isAdded) {
					stateFile.writeFile();
				}
			}
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((identity == null) ? 0 : identity.hashCode());
		result = prime * result
				+ ((nickname == null) ? 0 : nickname.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GuardEntryImpl other = (GuardEntryImpl) obj;
		if (identity == null) {
			if (other.identity != null)
				return false;
		} else if (!identity.equals(other.identity))
			return false;
		if (nickname == null) {
			if (other.nickname != null)
				return false;
		} else if (!nickname.equals(other.nickname))
			return false;
		return true;
	}
}
