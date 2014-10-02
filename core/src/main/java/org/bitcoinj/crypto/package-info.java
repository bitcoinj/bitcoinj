/**
 * The crypto package contains classes that work with key derivation algorithms like scrypt (passwords to AES keys),
 * BIP 32 hierarchies (chains of keys from a root seed), X.509 utilities for the payment protocol and other general
 * cryptography tasks. It also contains a class that can disable the (long since obsolete) DRM Java/US Govt imposes
 * on strong crypto. This is legal because Oracle got permission to ship strong AES to everyone years ago but hasn't
 * bothered to actually remove the logic barriers.
 */
package org.bitcoinj.crypto;