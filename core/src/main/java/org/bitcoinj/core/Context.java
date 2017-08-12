/*
 * Copyright by the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import org.bitcoinj.wallet.SendRequest;
import org.slf4j.*;

import static com.google.common.base.Preconditions.*;

// TODO: Finish adding Context c'tors to all the different objects so we can start deprecating the versions that take NetworkParameters.
// TODO: Add a working directory notion to Context and make various subsystems that want to use files default to that directory (eg. Orchid, block stores, wallet, etc).
// TODO: Auto-register the block chain object here, and then use it in the (newly deprecated) TransactionConfidence.getDepthInBlocks() method: the new version should take an AbstractBlockChain specifically.
//       Also use the block chain object reference from the context in PeerGroup and remove the other constructors, as it's easy to forget to wire things up.
// TODO: Move Threading.USER_THREAD to here and leave behind just a source code stub. Allow different instantiations of the library to use different user threads.
// TODO: Keep a URI to where library internal data files can be found, to abstract over the lack of JAR files on Android.
// TODO: Stash anything else that resembles global library configuration in here and use it to clean up the rest of the API without breaking people.

/**
 * <p>The Context object holds various objects and pieces of configuration that are scoped to a specific instantiation of
 * bitcoinj for a specific network. You can get an instance of this class through calling {@link #get()}.</p>
 *
 * <p>Context is new in 0.13 and the library is currently in a transitional period: you should create a Context that
 * wraps your chosen network parameters before using the rest of the library. However if you don't, things will still
 * work as a Context will be created for you and stashed in thread local storage. The context is then propagated between
 * library created threads as needed. This automagical propagation and creation is a temporary mechanism: one day it
 * will be removed to avoid confusing edge cases that could occur if the developer does not fully understand it e.g.
 * in the case where multiple instances of the library are in use simultaneously.</p>
 */
public class Context {
    private static final Logger log = LoggerFactory.getLogger(Context.class);

    public static final int DEFAULT_EVENT_HORIZON = 100;

    final private TxConfidenceTable confidenceTable;
    final private NetworkParameters params;
    final private int eventHorizon;
    final private boolean ensureMinRequiredFee;
    final private Coin feePerKb;

    /**
     * Creates a new context object. For now, this will be done for you by the framework. Eventually you will be
     * expected to do this yourself in the same manner as fetching a NetworkParameters object (at the start of your app).
     *
     * @param params The network parameters that will be associated with this context.
     */
    public Context(NetworkParameters params) {
        this(params, DEFAULT_EVENT_HORIZON, Transaction.DEFAULT_TX_FEE, true);
    }

    /**
     * Creates a new custom context object. This is mainly meant for unit tests for now.
     *
     * @param params The network parameters that will be associated with this context.
     * @param eventHorizon Number of blocks after which the library will delete data and be unable to always process reorgs (see {@link #getEventHorizon()}.
     * @param feePerKb The default fee per 1000 bytes of transaction data to pay when completing transactions. For details, see {@link SendRequest#feePerKb}.
     * @param ensureMinRequiredFee Whether to ensure the minimum required fee by default when completing transactions. For details, see {@link SendRequest#ensureMinRequiredFee}.
     */
    public Context(NetworkParameters params, int eventHorizon, Coin feePerKb, boolean ensureMinRequiredFee) {
        log.info("Creating bitcoinj {} context.", VersionMessage.BITCOINJ_VERSION);
        this.confidenceTable = new TxConfidenceTable();
        this.params = params;
        this.eventHorizon = eventHorizon;
        this.ensureMinRequiredFee = ensureMinRequiredFee;
        this.feePerKb = feePerKb;
        lastConstructed = this;
        slot.set(this);
    }

    private static volatile Context lastConstructed;
    private static boolean isStrictMode;
    private static final ThreadLocal<Context> slot = new ThreadLocal<>();

    /**
     * Returns the current context that is associated with the <b>calling thread</b>. BitcoinJ is an API that has thread
     * affinity: much like OpenGL it expects each thread that accesses it to have been configured with a global Context
     * object. This method returns that. Note that to help you develop, this method will <i>also</i> propagate whichever
     * context was created last onto the current thread, if it's missing. However it will print an error when doing so
     * because propagation of contexts is meant to be done manually: this is so two libraries or subsystems that
     * independently use bitcoinj (or possibly alt coin forks of it) can operate correctly.
     *
     * @throws java.lang.IllegalStateException if no context exists at all or if we are in strict mode and there is no context.
     */
    public static Context get() {
        Context tls = slot.get();
        if (tls == null) {
            if (isStrictMode) {
                log.error("Thread is missing a bitcoinj context.");
                log.error("You should use Context.propagate() or a ContextPropagatingThreadFactory.");
                throw new IllegalStateException("missing context");
            }
            if (lastConstructed == null)
                throw new IllegalStateException("You must construct a Context object before using bitcoinj!");
            slot.set(lastConstructed);
            log.error("Performing thread fixup: you are accessing bitcoinj via a thread that has not had any context set on it.");
            log.error("This error has been corrected for, but doing this makes your app less robust.");
            log.error("You should use Context.propagate() or a ContextPropagatingThreadFactory.");
            log.error("Please refer to the user guide for more information about this.");
            log.error("Thread name is {}.", Thread.currentThread().getName());
            // TODO: Actually write the user guide section about this.
            // TODO: If the above TODO makes it past the 0.13 release, kick Mike and tell him he sucks.
            return lastConstructed;
        } else {
            return tls;
        }
    }

    /**
     * Require that new threads use {@link #propagate(Context)} or {@link org.bitcoinj.utils.ContextPropagatingThreadFactory},
     * rather than using a heuristic for the desired context.
     */
    public static void enableStrictMode() {
        isStrictMode = true;
    }

    // A temporary internal shim designed to help us migrate internally in a way that doesn't wreck source compatibility.
    public static Context getOrCreate(NetworkParameters params) {
        Context context;
        try {
            context = get();
        } catch (IllegalStateException e) {
            log.warn("Implicitly creating context. This is a migration step and this message will eventually go away.");
            context = new Context(params);
            return context;
        }
        if (context.getParams() != params)
            throw new IllegalStateException("Context does not match implicit network params: " + context.getParams() + " vs " + params);
        return context;
    }

    /**
     * Sets the given context as the current thread context. You should use this if you create your own threads that
     * want to create core BitcoinJ objects. Generally, if a class can accept a Context in its constructor and might
     * be used (even indirectly) by a thread, you will want to call this first. Your task may be simplified by using
     * a {@link org.bitcoinj.utils.ContextPropagatingThreadFactory}.
     */
    public static void propagate(Context context) {
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

    /**
     * Returns the {@link org.bitcoinj.core.NetworkParameters} specified when this context was (auto) created. The
     * network parameters defines various hard coded constants for a specific instance of a Bitcoin network, such as
     * main net, testnet, etc.
     */
    public NetworkParameters getParams() {
        return params;
    }

    /**
     * The event horizon is the number of blocks after which various bits of the library consider a transaction to be
     * so confirmed that it's safe to delete data. Re-orgs larger than the event horizon will not be correctly
     * processed, so the default value is high (100).
     */
    public int getEventHorizon() {
        return eventHorizon;
    }

    /**
     * The default fee per 1000 bytes of transaction data to pay when completing transactions. For details, see {@link SendRequest#feePerKb}.
     */
    public Coin getFeePerKb() {
        return feePerKb;
    }

    /**
     * Whether to ensure the minimum required fee by default when completing transactions. For details, see {@link SendRequest#ensureMinRequiredFee}.
     */
    public boolean isEnsureMinRequiredFee() {
        return ensureMinRequiredFee;
    }
}
