package org.bitcoinj.store;

import sun.misc.*;
import sun.nio.ch.*;

import java.nio.*;

/**
 * <p>This class knows how to force an mmap'd ByteBuffer to reliquish its file handles before it becomes garbage collected,
 * by exploiting implementation details of the HotSpot JVM implementation.</p>
 *
 * <p>This is required on Windows because otherwise an attempt to delete a file that is still mmapped will fail. This can
 * happen when a user requests a "restore from seed" function, which involves deleting and recreating the chain file.
 * At some point we should stop using mmap in SPVBlockStore and we can then delete this class.</p>
 *
 * <p>It is a separate class to avoid hitting unknown imports when running on other JVMs.</p>
 */
public class WindowsMMapHack {
    public static void forceRelease(MappedByteBuffer buffer) {
        Cleaner cleaner = ((DirectBuffer) buffer).cleaner();
        if (cleaner != null) cleaner.clean();
    }
}
