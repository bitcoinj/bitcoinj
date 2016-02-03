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

package org.bitcoinj.core;

/**
 * <p>Represents the "getaddr" P2P protocol message, which requests network {@link AddressMessage}s from a peer. Not to
 * be confused with {@link Address} which is sort of like an account number.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class GetAddrMessage extends EmptyMessage {

    public GetAddrMessage(NetworkParameters params) {
        super(params);
    }
}
