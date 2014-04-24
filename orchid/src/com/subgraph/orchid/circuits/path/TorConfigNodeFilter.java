package com.subgraph.orchid.circuits.path;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;

public class TorConfigNodeFilter {
	
	/* 
	 * Even though these are exactly the configuration file variable names, they are only
	 * used here as keys into a Map<String,ConfigNodeFilter>
	 */
	private final static String EXCLUDE_NODES_FILTER = "ExcludeNodes";
	private final static String EXCLUDE_EXIT_NODES_FILTER = "ExcludeExitNodes";
	private final static String ENTRY_NODES_FILTER = "EntryNodes";
	private final static String EXIT_NODES_FILTER = "ExitNodes";
	
	private final Map<String, ConfigNodeFilter> filters;
	
	TorConfigNodeFilter(TorConfig config) {
		this.filters = new HashMap<String, ConfigNodeFilter>();
		addFilter(filters, EXCLUDE_NODES_FILTER, config.getExcludeNodes());
		addFilter(filters, EXCLUDE_EXIT_NODES_FILTER, config.getExcludeExitNodes());
		addFilter(filters, ENTRY_NODES_FILTER, config.getEntryNodes());
		addFilter(filters, EXIT_NODES_FILTER, config.getExitNodes());
	}
	
	private static void addFilter(Map<String, ConfigNodeFilter> filters, String name, List<String> filterStrings) {
		if(filterStrings == null || filterStrings.isEmpty()) {
			return;
		}
		filters.put(name, ConfigNodeFilter.createFromStrings(filterStrings));
	}
	
	List<Router> filterExitCandidates(List<Router> candidates) {
		final List<Router> filtered = new ArrayList<Router>();
		for(Router r: candidates) {
			if(isExitNodeIncluded(r)) {
				filtered.add(r);
			}
		}
		return filtered;
	}

	boolean isExitNodeIncluded(Router exitRouter) {
		return isIncludedByFilter(exitRouter, EXIT_NODES_FILTER) && 
				!(isExcludedByFilter(exitRouter, EXCLUDE_EXIT_NODES_FILTER) || 
						isExcludedByFilter(exitRouter, EXCLUDE_NODES_FILTER));
	}
	
	boolean isIncludedByFilter(Router r, String filterName) {
		final ConfigNodeFilter f = filters.get(filterName);
		if(f == null || f.isEmpty()) {
			return true;
		}
		return f.filter(r);
	}
	
	boolean isExcludedByFilter(Router r, String filterName) {
		final ConfigNodeFilter f = filters.get(filterName);
		if(f == null || f.isEmpty()) {
			return false;
		}
		return f.filter(r);
	}
}
