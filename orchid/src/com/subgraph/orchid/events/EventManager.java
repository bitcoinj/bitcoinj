package com.subgraph.orchid.events;

import java.util.ArrayList;
import java.util.List;

public class EventManager {
	private final List<EventHandler> handlers = new ArrayList<EventHandler>();
	
	public void addListener(final EventHandler listener) {
		synchronized(this) {
			handlers.add(listener);
		}
	}
	
	public void removeListener(final EventHandler listener) {
		synchronized(this) {
			handlers.remove(listener);
		}
	}
	
	public void fireEvent(final Event event) {
		EventHandler[] handlersCopy;
		
		synchronized(this) {
			handlersCopy = new EventHandler[handlers.size()];
			handlers.toArray(handlersCopy);
		}
		for(EventHandler handler : handlersCopy) {
			handler.handleEvent(event);
		}
		
	}

}
