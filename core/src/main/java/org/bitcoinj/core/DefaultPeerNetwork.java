package org.bitcoinj.core;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class DefaultPeerNetwork implements PeerNetwork {
    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    private final Network Network;
    private final Context context;

    private static final Object DEFAULT_LOCK = new Object();
    private static DefaultPeerNetwork defaultInstance;   // guarded by DEFAULT_LOCK

    public static DefaultPeerNetwork getDefault() {
        synchronized (DEFAULT_LOCK) {
            if (defaultInstance == null) {
                new DefaultPeerNetwork(BitcoinNetwork.TESTNET);   // registers itself via claimDefaultIfUnset()
            }
            return defaultInstance;
        }
    }
    
    public static DefaultPeerNetwork initialize(Network net) {
        synchronized (DEFAULT_LOCK) {
            if (defaultInstance == null) {
                log.info("Initializing defaultInstance of DefaultPeerNetwork on: {}", net);
                new DefaultPeerNetwork(net);   // registers itself via claimDefaultIfUnset()
            }
            return defaultInstance;
        }
    }

    public DefaultPeerNetwork(Network network) {
        this(network, new Context());
    }

    public DefaultPeerNetwork(Network network, Context context) {
        this.Network = network;
        this.context = context;
        Context.setThreadLocal(context);
        claimDefaultIfUnset();
    }

    private void claimDefaultIfUnset() {
        synchronized (DEFAULT_LOCK) {
            if (defaultInstance == null) {
                defaultInstance = this;
            }
        }
    }

    @Override
    public Network network() {
        return Network;
    }

    @Override
    public TxConfidenceTable txConfidenceTable() {
        return context.getConfidenceTable();
    }

    /**
     * Initialize the Context ThreadLocal on the current thread.
     * This is a temporary solution, while phasing out Context.
     * This will become a deprecated no-op when use of thread-local is no longer necessary.
     */
    public void initThreadLocal() {
        Context.setThreadLocal(context);
    }

    /**
     * Get the Context (reminder: Context will soon be deprecated)
     * @return context for this PeerNetwork
     */
    Context getContext() {
        return context;
    }
}
