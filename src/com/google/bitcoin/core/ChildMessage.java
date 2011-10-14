package com.google.bitcoin.core;

/**
 * Represents a Message type that can be contained within another Message.  ChildMessages that have a cached
 * backing byte array need to invalidate their parent's caches as well as their own if they are modified.
 *
 * @author git
 */
public abstract class ChildMessage extends Message {

    private Message parent;

    protected ChildMessage() {
    }

    public ChildMessage(NetworkParameters params) {
        super(params);
    }

    public ChildMessage(NetworkParameters params, byte[] msg, int offset, int protocolVersion) throws ProtocolException {
        super(params, msg, offset, protocolVersion);
    }

    public ChildMessage(NetworkParameters params, byte[] msg, int offset, int protocolVersion, Message parent, boolean parseLazy,
                        boolean parseRetain, int length) throws ProtocolException {
        super(params, msg, offset, protocolVersion, parseLazy, parseRetain, length);
        this.parent = parent;
    }

    public ChildMessage(NetworkParameters params, byte[] msg, int offset) throws ProtocolException {
        super(params, msg, offset);
    }

    public ChildMessage(NetworkParameters params, byte[] msg, int offset, Message parent, boolean parseLazy, boolean parseRetain, int length)
            throws ProtocolException {
        super(params, msg, offset, parseLazy, parseRetain, length);
        this.parent = parent;
    }

    public void setParent(Message parent) {
        if (this.parent != null && this.parent != parent && parent != null) {
            //after old parent is unlinked it won't be able to receive notice if this ChildMessage
            //changes internally.  To be safe we invalidate the parent cache to ensure it rebuilds
            //manually on serialization.
            this.parent.unCache();
        }
        this.parent = parent;
    }

    /* (non-Javadoc)
      * @see com.google.bitcoin.core.Message#unCache()
      */
    @Override
    protected void unCache() {
        super.unCache();
        if (parent != null)
            parent.unCache();
    }

    protected void adjustLength(int adjustment) {
        if (length != UNKNOWN_LENGTH)
            length += adjustment;
        if (parent != null)
            parent.adjustLength(adjustment);
    }

}
