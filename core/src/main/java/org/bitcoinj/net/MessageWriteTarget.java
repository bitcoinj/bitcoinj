/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.net;

import org.bitcoinj.utils.ListenableCompletableFuture;

import java.io.IOException;

/**
 * A target to which messages can be written/connection can be closed
 */
public interface MessageWriteTarget {
    /**
     * Writes the given bytes to the remote server. The returned future will complete when all bytes
     * have been written to the OS network buffer.
     */
    ListenableCompletableFuture<Void> writeBytes(byte[] message) throws IOException;
    /**
     * Closes the connection to the server, triggering the {@link StreamConnection#connectionClosed()}
     * event on the network-handling thread where all callbacks occur.
     */
    void closeConnection();
}
