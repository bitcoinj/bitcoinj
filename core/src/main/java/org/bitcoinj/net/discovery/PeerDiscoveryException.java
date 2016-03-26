/*
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.net.discovery;

public class PeerDiscoveryException extends Exception {
    private static final long serialVersionUID = -2863411151549391392L;

    public PeerDiscoveryException() {
        super();
    }

    public PeerDiscoveryException(String message) {
        super(message);
    }

    public PeerDiscoveryException(Throwable arg0) {
        super(arg0);
    }

    public PeerDiscoveryException(String message, Throwable arg0) {
        super(message, arg0);
    }
}
