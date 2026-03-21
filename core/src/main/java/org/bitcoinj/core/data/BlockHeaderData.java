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

package org.bitcoinj.core.data;

import org.bitcoinj.base.Sha256Hash;

import java.time.Instant;

/**
 * Implementations SHOULD be immutable.
 * getHash() may be present/precomputed, computed each time or computed lazily.
 * Implement {@link Hashed#hash()} if the Block hash is precomputed and returnable without computation.
 * The use of existing concrete types will be replaced as our immutable implementations get further along.
 */
public interface BlockHeaderData {
    long version();   // TODO: Should this be long or int?
    Sha256Hash prevHash();
    Sha256Hash merkleRoot();
    Instant time();
    long bits();       // TODO: Should this be long, int, or a DifficultyTarget type?
    long nonce();      // TODO: long or int?
    // This _may_ compute or compute-and-memoize the hash, there is no performance guarantee
    Sha256Hash getHash();
}
