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

/**
 * The crypto package contains classes that work with key derivation algorithms like scrypt (passwords to AES keys),
 * BIP 32 hierarchies (chains of keys from a root seed), X.509 utilities for the payment protocol and other general
 * cryptography tasks. It also contains a class that can disable the (long since obsolete) DRM Java/US Govt imposes
 * on strong crypto. This is legal because Oracle got permission to ship strong AES to everyone years ago but hasn't
 * bothered to actually remove the logic barriers.
 */
package org.bitcoinj.crypto;