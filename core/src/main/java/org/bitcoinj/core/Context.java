package org.bitcoinj.core;

import org.slf4j.*;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * The Context object holds various objects that are scoped to a specific instantiation of bitcoinj for a specific
 * network. You can get an instance of this class through {@link AbstractBlockChain#getContext()}. At the momemnt it
 * only contains a {@link org.bitcoinj.core.TxConfidenceTable} but in future it will likely contain file paths and
 * other global configuration of use.
 */
public class Context {
    private static final Logger log = LoggerFactory.getLogger(Context.class);
    protected TxConfidenceTable confidenceTable;

    /**
     * Creates a new context object. For now, this will be done for you by the framework. Eventually you will be
     * expected to do this yourself in the same manner as fetching a NetworkParameters object (at the start of your app).
     */
    public Context() {
        confidenceTable = new TxConfidenceTable();
        lastConstructed = this;
        // We may already have a context in our TLS slot. This can happen a lot during unit tests, so just ignore it.
        slot.set(this);
    }

    private static volatile Context lastConstructed;
    private static final ThreadLocal<Context> slot = new ThreadLocal<Context>();

    /**
     * Returns the current context that is associated with the <b>calling thread</b>. BitcoinJ is an API that has thread
     * affinity: much like OpenGL it expects each thread that accesses it to have been configured with a global Context
     * object. This method returns that. Note that to help you develop, this method will <i>also</i> propagate whichever
     * context was created last onto the current thread, if it's missing. However it will print an error when doing so
     * because propagation of contexts is meant to be done manually: this is so two libraries or subsystems that
     * independently use bitcoinj (or possibly alt coin forks of it) can operate correctly.
     *
     * @throws java.lang.IllegalStateException if no context exists at all.
     */
    public static Context get() {
        Context tls = slot.get();
        if (tls == null) {
            if (lastConstructed == null)
                throw new IllegalStateException("You must construct a Context object before using bitcoinj!");
            slot.set(lastConstructed);
            log.error("Performing thread fixup: you are accessing bitcoinj via a thread that has not had any context set on it.");
            log.error("This error has been corrected for, but doing this makes your app less robust.");
            log.error("You should use Context.propagate() or a ContextPropagatingThreadFactory.");
            log.error("Please refer to the user guide for more information about this.");
            // TODO: Actually write the user guide section about this.
            // TODO: If the above TODO makes it past the 0.13 release, kick Mike and tell him he sucks.
            return lastConstructed;
        } else {
            return tls;
        }
    }

    // A temporary internal shim designed to help us migrate internally in a way that doesn't wreck source compatibility.
    static Context getOrCreate() {
        try {
            return get();
        } catch (IllegalStateException e) {
            log.warn("Implicitly creating context. This is a migration step and this message will eventually go away.");
            new Context();
            return slot.get();
        }
    }

    /**
     * Sets the given context as the current thread context. You should use this if you create your own threads that
     * want to create core BitcoinJ objects. Generally, if a class can accept a Context in its constructor and might
     * be used (even indirectly) by a thread, you will want to call this first. Your task may be simplified by using
     * a {@link org.bitcoinj.utils.ContextPropagatingThreadFactory}.
     *
     * @throws java.lang.IllegalStateException if this thread already has a context
     */
    public static void propagate(Context context) {
        checkState(slot.get() == null);
        slot.set(checkNotNull(context));
    }

    /**
     * Returns the {@link TxConfidenceTable} created by this context. The pool tracks advertised
     * and downloaded transactions so their confidence can be measured as a proportion of how many peers announced it.
     * With an un-tampered with internet connection, the more peers announce a transaction the more confidence you can
     * have that it's really valid.
     */
    public TxConfidenceTable getConfidenceTable() {
        return confidenceTable;
    }
}
