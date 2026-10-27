# Fork

Upstream: https://github.com/bitcoinj/bitcoinj
Versioning: <upstream-version>-dwdc.<N>

Local patches:
- HD path parsing accepts `h` and `'` hardened suffixes; upstream
  accepts only `H`.
- `toString(char hardeningSymbol)` on `ChildNumber` and `HDPath`.
- BouncyCastle `bcprov-jdk18on` in place of `bcprov-jdk15to18`.
