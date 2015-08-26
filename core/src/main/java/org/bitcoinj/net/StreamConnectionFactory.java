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

import java.net.InetAddress;
import javax.annotation.Nullable;

/**
 * A factory which generates new {@link StreamConnection}s when a new connection is opened.
 */
public interface StreamConnectionFactory {
    /**
     * Returns a new handler or null to have the connection close.
     * @param inetAddress The client's (IP) address
     * @param port The remote port on the client side
     */
    @Nullable
    StreamConnection getNewConnection(InetAddress inetAddress, int port);
}
