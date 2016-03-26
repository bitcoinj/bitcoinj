/*
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
