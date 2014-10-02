/**
 * Block stores persist blockchain data downloaded from remote peers. There is an SPV block store which preserves a ring
 * buffer of headers on disk and is suitable for lightweight user wallets, a store that's backed by Postgres and which
 * can calculate a full indexed UTXO set (i.e. it can query address balances), a store that's backed by the embedded H2
 * database, and a memory only store useful for unit tests.
 */
package org.bitcoinj.store;