/**
 * Copyright 2011 Noa Resare.
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

package com.google.bitcoin.core;

/**
 * The verack message, sent by a client accepting the version message they
 * received from their peer.
 */
public class VersionAck extends EmptyMessage {
    public VersionAck() {

    }

    // this is needed by the BitcoinSerializer
    public VersionAck(NetworkParameters params, byte[] payload) {

    }

}
