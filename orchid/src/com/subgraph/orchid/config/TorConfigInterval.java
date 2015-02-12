package com.subgraph.orchid.config;

import java.util.concurrent.TimeUnit;

public class TorConfigInterval {

	public static TorConfigInterval createFrom(String s) {
		final String[] ss = s.split(" ");
		final long n = Long.parseLong(ss[0]);
		if(ss.length == 1) {
			return new TorConfigInterval(n, TimeUnit.SECONDS);
		} else {
			return createForValueAndUnit(n, ss[1]);
		}
	}
	
	private static TorConfigInterval createForValueAndUnit(long value, String unitName) {
		if(stringMatchesUnit(unitName, "week")) {
			return new TorConfigInterval(value * 7, TimeUnit.DAYS);
		} else {
			final TimeUnit unit = stringToUnit(unitName);
			return new TorConfigInterval(value, unit);
		}
	}
	
	private static TimeUnit stringToUnit(String s) {
		if(stringMatchesUnit(s, "day")) {
			return TimeUnit.DAYS;
		} else if(stringMatchesUnit(s, "hour")) {
			return TimeUnit.HOURS;
		} else if(stringMatchesUnit(s, "minute")) {
			return TimeUnit.MINUTES;
		} else if(stringMatchesUnit(s, "second")) {
			return TimeUnit.SECONDS;
		} else if(stringMatchesUnit(s, "millisecond")) {
			return TimeUnit.MILLISECONDS;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	private static boolean stringMatchesUnit(String s, String unitType) {
		if(s == null) {
			return false;
		} else {
			return s.equalsIgnoreCase(unitType) || s.equalsIgnoreCase(unitType + "s");
		}
	}
	
	private final TimeUnit timeUnit;
	private final long value;


	public TorConfigInterval(long value, TimeUnit timeUnit) {
		this.timeUnit = getTimeUnitFor(value, timeUnit);
		this.value = getValueFor(value, timeUnit);

	}
	
	public long getMilliseconds() {
		return TimeUnit.MILLISECONDS.convert(value, timeUnit);
	}

	private static TimeUnit getTimeUnitFor(long value, TimeUnit timeUnit) {
		if(timeUnit == TimeUnit.NANOSECONDS || timeUnit == TimeUnit.MICROSECONDS) {
			return TimeUnit.MILLISECONDS;
		} else {
			return timeUnit;
		}
	}
	
	private static long getValueFor(long value, TimeUnit timeUnit) {
		if(timeUnit == TimeUnit.NANOSECONDS || timeUnit == TimeUnit.MICROSECONDS) {
			return TimeUnit.MILLISECONDS.convert(value, timeUnit);
		} else {
			return value;
		}
	}

	public String toString() {
		if(timeUnit == TimeUnit.DAYS && (value % 7 == 0)) {
			final long weeks = value / 7;
			return (weeks == 1) ? "1 week" : (weeks + " weeks");
		}
		final StringBuilder sb = new StringBuilder();
		sb.append(value);
		sb.append(" ");
		sb.append(unitToString(timeUnit));
		if(value != 1) {
			sb.append("s");
		}
		return sb.toString();
	}
	
	private static String unitToString(TimeUnit unit) {
		switch(unit) {
		case MILLISECONDS:
			return "millisecond";
		case SECONDS:
			return "second";
		case MINUTES:
			return "minute";
		case HOURS:
			return "hour";
		case DAYS:
			return "days";
		default:
			throw new IllegalArgumentException();
		}
	}
}
