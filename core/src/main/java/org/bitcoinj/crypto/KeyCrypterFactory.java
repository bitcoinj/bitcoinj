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

package org.bitcoinj.crypto;

import org.bitcoinj.protobuf.wallet.Protos;

/**
 * The {@code KeyCrypterFactory} interface defines a factory pattern for creating instances of {@code KeyCrypter}.
 * This factory interface is utilized to abstract the creation process of {@code KeyCrypter} objects, allowing for
 * flexible implementations of {@code KeyCrypterScrypt} subclasses that can be swapped easily without altering the 
 * BitcoinJ code base.
 */
public interface KeyCrypterFactory {
    /**
     * Creates and returns a new instance of a {@code KeyCrypter}. The specific type and configuration of the
     * {@code KeyCrypter} returned depend on the implementation of this factory. Each call to this method should
     * return a new, independent instance of a {@code KeyCrypter}.
     *
     *
     * @return a newly created instance of {@code KeyCrypter}.
     */
    KeyCrypter createKeyCrypter();
}
